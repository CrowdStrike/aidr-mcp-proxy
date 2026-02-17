#!/usr/bin/env node

import { AIGuard } from '@crowdstrike/aidr';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  type CallToolResult,
  CompleteRequestSchema,
  GetPromptRequestSchema,
  type Implementation,
  ListPromptsRequestSchema,
  ListResourcesRequestSchema,
  ListResourceTemplatesRequestSchema,
  ListToolsRequestSchema,
  type ListToolsResult,
  LoggingMessageNotificationSchema,
  ReadResourceRequestSchema,
  ResourceUpdatedNotificationSchema,
  SubscribeRequestSchema,
  UnsubscribeRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { defineCommand, runMain } from 'citty';
import { consola } from 'consola';

const main = defineCommand({
  args: {},
  async run({ args }) {
    if (!process.env.CS_AIDR_TOKEN) {
      throw new Error('Missing environment variable: CS_AIDR_TOKEN');
    }

    if (!process.env.CS_AIDR_BASE_URL_TEMPLATE) {
      throw new Error(
        'Missing environment variable: CS_AIDR_BASE_URL_TEMPLATE'
      );
    }

    if (args._.length < 1) {
      consola.error('No command provided.');
      process.exit(1);
    }

    const clientTransport = new StdioClientTransport({
      command: args._[0],
      args: args._.slice(1),
      env: process.env as Record<string, string>,
    });
    const client = new Client(
      {
        name: 'cs-aidr-mcp-proxy-client',
        version: '1.0.0',
      },
      {
        capabilities: {},
      }
    );

    await client.connect(clientTransport);

    const serverTransport = new StdioServerTransport();
    const serverCapabilities = client.getServerCapabilities();
    const serverVersion: Implementation = client.getServerVersion()!;
    const server = new Server(serverVersion, {
      capabilities: serverCapabilities,
    });

    if (serverCapabilities?.logging) {
      server.setNotificationHandler(LoggingMessageNotificationSchema, (args) =>
        client.notification(args)
      );
    }

    if (serverCapabilities?.prompts) {
      server.setRequestHandler(GetPromptRequestSchema, (args) =>
        client.getPrompt(args.params)
      );
      server.setRequestHandler(ListPromptsRequestSchema, (args) =>
        client.listPrompts(args.params)
      );
    }

    if (serverCapabilities?.resources) {
      server.setRequestHandler(ListResourcesRequestSchema, (args) =>
        client.listResources(args.params)
      );
      server.setRequestHandler(ListResourceTemplatesRequestSchema, (args) =>
        client.listResourceTemplates(args.params)
      );
      server.setRequestHandler(ReadResourceRequestSchema, (args) =>
        client.readResource(args.params)
      );

      if (serverCapabilities?.resources.subscribe) {
        server.setNotificationHandler(
          ResourceUpdatedNotificationSchema,
          (args) => client.notification(args)
        );
        server.setRequestHandler(SubscribeRequestSchema, (args) =>
          client.subscribeResource(args.params)
        );
        server.setRequestHandler(UnsubscribeRequestSchema, (args) =>
          client.unsubscribeResource(args.params)
        );
      }
    }

    if (serverCapabilities?.tools) {
      const aiGuard = new AIGuard({
        token: process.env.CS_AIDR_TOKEN!,
        baseURLTemplate: process.env.CS_AIDR_BASE_URL_TEMPLATE!,
      });

      server.setRequestHandler(ListToolsRequestSchema, async (args) => {
        const response: ListToolsResult = await client.listTools(args.params);
        const { tools } = response;
        const guardedToolsList = await aiGuard.guardChatCompletions({
          guard_input: { messages: [], tools },
          app_id: process.env.APP_ID,
          event_type: 'tool_listing',
          extra_info: {
            app_name: process.env.APP_NAME,
            mcp_server_name: serverVersion.name,
          },
        });

        if (guardedToolsList.status !== 'Success') {
          throw new Error(
            `Failed to guard tools list. ${JSON.stringify(guardedToolsList, null, 2)}`
          );
        }

        return guardedToolsList.result?.blocked
          ? { ...response, tools: [] }
          : response;
      });

      server.setRequestHandler(CallToolRequestSchema, async (args) => {
        const guardedInput = await aiGuard.guardChatCompletions({
          guard_input: {
            messages: [
              {
                role: 'user',
                content: JSON.stringify(args.params.arguments) ?? '',
              },
            ],
          },
          app_id: process.env.APP_ID,
          event_type: 'tool_input',
          extra_info: {
            app_name: process.env.APP_NAME,
            mcp_server_name: serverVersion.name,
            tool_name: args.params.name,
          },
        });

        if (guardedInput.status !== 'Success') {
          throw new Error('Failed to guard input.');
        }

        if (guardedInput.result?.blocked) {
          const { guard_output, ...rest } = guardedInput.result;
          return {
            content: [
              {
                type: 'text',
                text: `Input has been blocked by CrowdStrike AIDR.\n\n${JSON.stringify(rest, null, 2)}`,
              },
            ],
          };
        }

        const newArgs: Record<string, unknown> = guardedInput.result
          ?.transformed
          ? JSON.parse(
              (
                guardedInput.result?.guard_output?.messages as {
                  content: string;
                }[]
              )[0].content ?? '{}'
            )
          : args.params.arguments;

        const response = (await client.callTool({
          ...args.params,
          arguments: newArgs,
        })) as CallToolResult;
        const { content, structuredContent } = response;

        if (structuredContent) {
          // Process structuredContent from tools that return it
          const guardedOutput = await aiGuard.guardChatCompletions({
            guard_input: {
              messages: [
                {
                  role: 'tool',
                  content: JSON.stringify(structuredContent),
                },
              ],
            },
            app_id: process.env.APP_ID,
            event_type: 'tool_output',
            extra_info: {
              app_name: process.env.APP_NAME,
              mcp_server_name: serverVersion.name,
              tool_name: args.params.name,
            },
          });

          if (guardedOutput.status !== 'Success') {
            throw new Error('Failed to guard output.');
          }

          if (guardedOutput.result?.blocked) {
            const { guard_output, ...rest } = guardedOutput.result;
            return {
              content: [
                {
                  type: 'text',
                  text: `Output has been blocked by CrowdStrike AIDR.\n\n${JSON.stringify(rest, null, 2)}`,
                },
              ],
            };
          }

          if (guardedOutput.result?.transformed) {
            const contentText = (
              guardedOutput.result.guard_output?.messages as {
                content: string;
              }[]
            )[0].content;

            try {
              response.structuredContent = JSON.parse(contentText);

              response.content = [
                {
                  type: 'text',
                  text: JSON.stringify(response.structuredContent),
                },
              ];
            } catch {
              response.content = [
                {
                  type: 'text',
                  text: contentText,
                },
              ];
            }
          }
        } else {
          // Process text content from tools that don't return structuredContent
          for (const contentItem of content.filter((c) => c.type === 'text')) {
            const guardedOutput = await aiGuard.guardChatCompletions({
              guard_input: {
                messages: [
                  {
                    role: 'tool',
                    content: contentItem.text,
                  },
                ],
              },
              app_id: process.env.APP_ID,
              event_type: 'tool_output',
              extra_info: {
                app_name: process.env.APP_NAME,
                mcp_server_name: serverVersion.name,
                tool_name: args.params.name,
              },
            });

            if (guardedOutput.status !== 'Success') {
              throw new Error('Failed to guard output.');
            }

            if (guardedOutput.result?.blocked) {
              const { guard_output, ...rest } = guardedOutput.result;
              return {
                content: [
                  {
                    type: 'text',
                    text: `Output has been blocked by CrowdStrike AIDR.\n\n${JSON.stringify(rest, null, 2)}`,
                  },
                ],
                isError: true,
              };
            }

            if (guardedOutput.result?.transformed) {
              contentItem.text = (
                guardedOutput.result.guard_output?.messages as {
                  content: string;
                }[]
              )[0].content;
            }
          }
        }

        return response;
      });
    }

    if (serverCapabilities?.completions) {
      server.setRequestHandler(CompleteRequestSchema, (args) =>
        client.complete(args.params)
      );
    }

    await server.connect(serverTransport);
  },
});

runMain(main);
