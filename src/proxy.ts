#!/usr/bin/env node

import { AIGuard } from '@crowdstrike/aidr';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { defineCommand, runMain } from 'citty';
import { consola } from 'consola';
import { EnvHttpProxyAgent } from 'undici';
import { createProxyServer } from './create-proxy-server.js';

const main = defineCommand({
  args: {},
  async run({ args }) {
    const token = process.env.CS_AIDR_TOKEN;
    if (!token) {
      throw new Error('Missing environment variable: CS_AIDR_TOKEN');
    }

    const baseURLTemplate = process.env.CS_AIDR_BASE_URL_TEMPLATE;
    if (!baseURLTemplate) {
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
      env: {
        ...process.env,
        CS_AIDR_TOKEN: undefined,
        CS_AIDR_USER_ID: undefined,
        CS_AIDR_USER_NAME: undefined,
      } as unknown as Record<string, string>,
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

    const dispatcher =
      new EnvHttpProxyAgent() as unknown as RequestInit['dispatcher'];
    const aiGuard = new AIGuard({
      token,
      baseURLTemplate,
      fetch: (url: string | URL | Request, init?: RequestInit) =>
        fetch(url, { ...init, dispatcher }),
    });

    const server = createProxyServer(client, aiGuard, {
      appId: process.env.APP_ID,
      appName: process.env.APP_NAME,
      userId: process.env.CS_AIDR_USER_ID,
      userName: process.env.CS_AIDR_USER_NAME,
    });

    const serverTransport = new StdioServerTransport();
    await server.connect(serverTransport);
  },
});

runMain(main);
