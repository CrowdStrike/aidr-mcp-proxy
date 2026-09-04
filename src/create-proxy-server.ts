import type { AIGuard } from '@crowdstrike/aidr';
import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  type CallToolResult,
  CompleteRequestSchema,
  type ContentBlock,
  GetPromptRequestSchema,
  type ImageContent,
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
  type TextContent,
  UnsubscribeRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

interface TextContentPart {
  type: 'text';
  text: string;
}

interface ImageUrl {
  url: string;
}

interface ImageUrlContentPart {
  type: 'image_url';
  image_url: ImageUrl;
}

type ContentPart = TextContentPart | ImageUrlContentPart;
type MessageContent = string | ContentPart[] | null;

function isTextContent(x: ContentBlock): x is TextContent {
  return x.type === 'text';
}

function isImageContent(x: ContentBlock): x is ImageContent {
  return x.type === 'image';
}

export interface ProxyIdentity {
  appId?: string;
  appName?: string;
  userId?: string;
  userName?: string;
}

/**
 * Builds the MCP server exposed to the proxy's caller, wiring every
 * request/notification through to the given (already-connected) upstream
 * client, with tool input/output guarded by AIDR.
 */
export function createProxyServer(
  client: Client,
  aiGuard: AIGuard,
  identity: ProxyIdentity = {}
): Server {
  const serverCapabilities = client.getServerCapabilities();
  const serverVersion: Implementation = client.getServerVersion()!;
  const server = new Server(serverVersion, {
    capabilities: serverCapabilities,
    instructions: client.getInstructions(),
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
      server.setNotificationHandler(ResourceUpdatedNotificationSchema, (args) =>
        client.notification(args)
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
    server.setRequestHandler(ListToolsRequestSchema, async (args) => {
      const response: ListToolsResult = await client.listTools(args.params);
      const { tools } = response;
      const guardedToolsList = await aiGuard.guardChatCompletions({
        guard_input: { messages: [], tools },
        app_id: identity.appId,
        event_type: 'tool_listing',
        user_id: identity.userId,
        extra_info: {
          app_name: identity.appName,
          mcp_server_name: serverVersion.name,
          user_name: identity.userName,
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
        app_id: identity.appId,
        event_type: 'tool_input',
        user_id: identity.userId,
        extra_info: {
          app_name: identity.appName,
          mcp_server_name: serverVersion.name,
          tool_name: args.params.name,
          user_name: identity.userName,
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
          isError: true,
        };
      }

      const guardedInputMessages = guardedInput.result?.guard_output
        ?.messages as { content: string }[] | undefined;
      const newArgs: Record<string, unknown> = guardedInput.result?.transformed
        ? JSON.parse(guardedInputMessages?.[0]?.content ?? '{}')
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
          app_id: identity.appId,
          event_type: 'tool_output',
          user_id: identity.userId,
          extra_info: {
            app_name: identity.appName,
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
          const structuredMessages = guardedOutput.result.guard_output
            ?.messages as { content: string }[] | undefined;
          const contentText = structuredMessages?.[0]?.content ?? '';

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
        // Process content from tools that don't return structuredContent.
        // Content types other than "text" and "image" are not supported by
        // CrowdStrike AIDR.
        for (const contentItem of content.filter(
          (c) => isTextContent(c) || isImageContent(c)
        )) {
          const content: MessageContent = isTextContent(contentItem)
            ? contentItem.text
            : [
                {
                  type: 'image_url',
                  image_url: {
                    url: `data:${contentItem.mimeType};base64,${contentItem.data}`,
                  },
                },
              ];
          const guardedOutput = await aiGuard.guardChatCompletions({
            guard_input: {
              messages: [
                {
                  role: 'tool',
                  content,
                },
              ],
            },
            app_id: identity.appId,
            event_type: 'tool_output',
            user_id: identity.userId,
            extra_info: {
              app_name: identity.appName,
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

          if (isTextContent(contentItem) && guardedOutput.result?.transformed) {
            const outputMessages = guardedOutput.result.guard_output
              ?.messages as { content: string }[] | undefined;
            contentItem.text = outputMessages?.[0]?.content ?? contentItem.text;
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

  return server;
}
