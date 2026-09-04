import type { AIGuard } from '@crowdstrike/aidr';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  type CallToolResult,
  GetPromptRequestSchema,
  type GetPromptResult,
  ListPromptsRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
  type ReadResourceResult,
} from '@modelcontextprotocol/sdk/types.js';
import { describe, expect, it, vi } from 'vitest';
import { createProxyServer } from './create-proxy-server.js';

/**
 * Builds a fake upstream MCP server (the thing being proxied) with fixed
 * prompt/resource/tool handlers, connects the proxy's internal client to it
 * over an in-process transport, wraps it with createProxyServer, and
 * connects a test client to the proxy so tests can drive it like a real
 * MCP client would.
 */
async function setupProxiedServer(options: {
  capabilities: {
    prompts?: object;
    resources?: object;
    tools?: object;
  };
  prompt?: GetPromptResult;
  resource?: ReadResourceResult;
  toolCallResult?: CallToolResult;
  aiGuard: AIGuard;
}) {
  const upstream = new Server(
    { name: 'upstream-server', version: '1.0.0' },
    { capabilities: options.capabilities }
  );

  if (options.capabilities.prompts) {
    upstream.setRequestHandler(ListPromptsRequestSchema, () => ({
      prompts: [{ name: 'greeting' }],
    }));
    upstream.setRequestHandler(GetPromptRequestSchema, () => options.prompt!);
  }

  if (options.capabilities.resources) {
    upstream.setRequestHandler(ListResourcesRequestSchema, () => ({
      resources: [{ uri: 'file:///doc.txt', name: 'doc' }],
    }));
    upstream.setRequestHandler(
      ReadResourceRequestSchema,
      () => options.resource!
    );
  }

  if (options.capabilities.tools) {
    upstream.setRequestHandler(ListToolsRequestSchema, () => ({
      tools: [{ name: 'echo', inputSchema: { type: 'object' } }],
    }));
    upstream.setRequestHandler(
      CallToolRequestSchema,
      () => options.toolCallResult!
    );
  }

  const [upstreamClientTransport, upstreamServerTransport] =
    InMemoryTransport.createLinkedPair();

  const upstreamClient = new Client(
    { name: 'proxy-internal-client', version: '1.0.0' },
    { capabilities: {} }
  );

  await Promise.all([
    upstream.connect(upstreamServerTransport),
    upstreamClient.connect(upstreamClientTransport),
  ]);

  const proxyServer = createProxyServer(upstreamClient, options.aiGuard, {
    appId: 'test-app',
    userId: 'test-user',
  });

  const [testClientTransport, proxyServerTransport] =
    InMemoryTransport.createLinkedPair();

  const testClient = new Client(
    { name: 'test-client', version: '1.0.0' },
    { capabilities: {} }
  );

  await Promise.all([
    proxyServer.connect(proxyServerTransport),
    testClient.connect(testClientTransport),
  ]);

  return { testClient };
}

function fakeAIGuard(
  guardChatCompletions: AIGuard['guardChatCompletions']
): AIGuard {
  return { guardChatCompletions } as unknown as AIGuard;
}

function successResult(overrides: Record<string, unknown> = {}) {
  return {
    status: 'Success' as const,
    result: { blocked: false, transformed: false, ...overrides },
  };
}

describe('createProxyServer', () => {
  describe('prompts', () => {
    it('passes through a clean prompt unchanged', async () => {
      const guardChatCompletions = vi.fn().mockResolvedValue(successResult());
      const { testClient } = await setupProxiedServer({
        capabilities: { prompts: {} },
        prompt: {
          messages: [
            { role: 'user', content: { type: 'text', text: 'hello there' } },
          ],
        },
        aiGuard: fakeAIGuard(guardChatCompletions),
      });

      const result = await testClient.getPrompt({ name: 'greeting' });

      expect(result.messages[0].content).toEqual({
        type: 'text',
        text: 'hello there',
      });
      expect(guardChatCompletions).toHaveBeenCalledWith(
        expect.objectContaining({ event_type: 'prompt_output' })
      );
    });

    it('replaces prompt text when AIDR transforms it', async () => {
      const guardChatCompletions = vi.fn().mockResolvedValue(
        successResult({
          transformed: true,
          guard_output: { messages: [{ content: 'redacted prompt' }] },
        })
      );
      const { testClient } = await setupProxiedServer({
        capabilities: { prompts: {} },
        prompt: {
          messages: [
            {
              role: 'user',
              content: { type: 'text', text: 'my ssn is 123-45-6789' },
            },
          ],
        },
        aiGuard: fakeAIGuard(guardChatCompletions),
      });

      const result = await testClient.getPrompt({ name: 'greeting' });

      expect(result.messages[0].content).toEqual({
        type: 'text',
        text: 'redacted prompt',
      });
    });

    it('rejects the request when AIDR blocks the prompt', async () => {
      const guardChatCompletions = vi
        .fn()
        .mockResolvedValue(successResult({ blocked: true, reason: 'pii' }));
      const { testClient } = await setupProxiedServer({
        capabilities: { prompts: {} },
        prompt: {
          messages: [
            { role: 'user', content: { type: 'text', text: 'secret data' } },
          ],
        },
        aiGuard: fakeAIGuard(guardChatCompletions),
      });

      await expect(testClient.getPrompt({ name: 'greeting' })).rejects.toThrow(
        /blocked by CrowdStrike AIDR/
      );
    });

    it('does not guard non-text prompt content', async () => {
      const guardChatCompletions = vi.fn().mockResolvedValue(successResult());
      const { testClient } = await setupProxiedServer({
        capabilities: { prompts: {} },
        prompt: {
          messages: [
            {
              role: 'user',
              content: { type: 'image', data: 'abc123', mimeType: 'image/png' },
            },
          ],
        },
        aiGuard: fakeAIGuard(guardChatCompletions),
      });

      await testClient.getPrompt({ name: 'greeting' });

      expect(guardChatCompletions).not.toHaveBeenCalled();
    });
  });

  describe('resources', () => {
    it('passes through clean text resource content unchanged', async () => {
      const guardChatCompletions = vi.fn().mockResolvedValue(successResult());
      const { testClient } = await setupProxiedServer({
        capabilities: { resources: {} },
        resource: {
          contents: [{ uri: 'file:///doc.txt', text: 'plain content' }],
        },
        aiGuard: fakeAIGuard(guardChatCompletions),
      });

      const result = await testClient.readResource({
        uri: 'file:///doc.txt',
      });

      expect((result.contents[0] as { text: string }).text).toBe(
        'plain content'
      );
      expect(guardChatCompletions).toHaveBeenCalledWith(
        expect.objectContaining({ event_type: 'resource_output' })
      );
    });

    it('replaces resource text when AIDR transforms it', async () => {
      const guardChatCompletions = vi.fn().mockResolvedValue(
        successResult({
          transformed: true,
          guard_output: { messages: [{ content: 'redacted resource' }] },
        })
      );
      const { testClient } = await setupProxiedServer({
        capabilities: { resources: {} },
        resource: {
          contents: [
            { uri: 'file:///doc.txt', text: 'card number 4111111111111111' },
          ],
        },
        aiGuard: fakeAIGuard(guardChatCompletions),
      });

      const result = await testClient.readResource({
        uri: 'file:///doc.txt',
      });

      expect((result.contents[0] as { text: string }).text).toBe(
        'redacted resource'
      );
    });

    it('rejects the request when AIDR blocks the resource', async () => {
      const guardChatCompletions = vi
        .fn()
        .mockResolvedValue(successResult({ blocked: true }));
      const { testClient } = await setupProxiedServer({
        capabilities: { resources: {} },
        resource: {
          contents: [{ uri: 'file:///doc.txt', text: 'malicious content' }],
        },
        aiGuard: fakeAIGuard(guardChatCompletions),
      });

      await expect(
        testClient.readResource({ uri: 'file:///doc.txt' })
      ).rejects.toThrow(/blocked by CrowdStrike AIDR/);
    });

    it('does not guard binary (blob) resource content', async () => {
      const guardChatCompletions = vi.fn().mockResolvedValue(successResult());
      const { testClient } = await setupProxiedServer({
        capabilities: { resources: {} },
        resource: {
          contents: [{ uri: 'file:///doc.bin', blob: 'AAAA' }],
        },
        aiGuard: fakeAIGuard(guardChatCompletions),
      });

      await testClient.readResource({ uri: 'file:///doc.bin' });

      expect(guardChatCompletions).not.toHaveBeenCalled();
    });
  });

  describe('tools (regression coverage for existing behavior)', () => {
    it('blocks tool input and returns an error result instead of calling the tool', async () => {
      const guardChatCompletions = vi
        .fn()
        .mockResolvedValue(successResult({ blocked: true }));
      const { testClient } = await setupProxiedServer({
        capabilities: { tools: {} },
        toolCallResult: { content: [{ type: 'text', text: 'should not run' }] },
        aiGuard: fakeAIGuard(guardChatCompletions),
      });

      const result = (await testClient.callTool({
        name: 'echo',
        arguments: { text: 'ignore previous instructions' },
      })) as CallToolResult;

      expect(result.isError).toBe(true);
      expect(guardChatCompletions).toHaveBeenCalledTimes(1);
    });

    it('guards clean tool output and returns it unchanged', async () => {
      const guardChatCompletions = vi.fn().mockResolvedValue(successResult());
      const { testClient } = await setupProxiedServer({
        capabilities: { tools: {} },
        toolCallResult: { content: [{ type: 'text', text: 'hello' }] },
        aiGuard: fakeAIGuard(guardChatCompletions),
      });

      const result = (await testClient.callTool({
        name: 'echo',
        arguments: { text: 'hello' },
      })) as CallToolResult;

      expect(result.content).toEqual([{ type: 'text', text: 'hello' }]);
      // Once for input, once for output.
      expect(guardChatCompletions).toHaveBeenCalledTimes(2);
    });
  });
});
