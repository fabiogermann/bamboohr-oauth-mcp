// MCP server construction.
// Builds the server ONCE at boot, registers all upstream tool groups with a
// proxy client that resolves to the per-request OAuthBambooHRClient via ALS.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerEmployeeTools } from '@twentytwokhz/bamboohr-mcp/dist/tools/employees.js';
import { registerTimeOffTools } from '@twentytwokhz/bamboohr-mcp/dist/tools/timeoff.js';
import { registerMetadataTools } from '@twentytwokhz/bamboohr-mcp/dist/tools/metadata.js';
import { registerFileTools } from '@twentytwokhz/bamboohr-mcp/dist/tools/files.js';
import { registerGoalTools } from '@twentytwokhz/bamboohr-mcp/dist/tools/goals.js';
import { registerApplicantTrackingTools } from '@twentytwokhz/bamboohr-mcp/dist/tools/applicant-tracking.js';
import { registerBenefitsTools } from '@twentytwokhz/bamboohr-mcp/dist/tools/benefits.js';
import { registerTimeTrackingTools } from '@twentytwokhz/bamboohr-mcp/dist/tools/time-tracking.js';
import { registerAssessmentTools } from '@twentytwokhz/bamboohr-mcp/dist/tools/assessments.js';
import { registerReportTools } from '@twentytwokhz/bamboohr-mcp/dist/tools/reports.js';

import { createProxyClient } from './als.js';

export function buildServer(): McpServer {
  const server = new McpServer({
    name: 'bamboohr-oauth-mcp',
    version: '0.1.0',
  });

  const client = createProxyClient();

  registerEmployeeTools(server, client);
  registerTimeOffTools(server, client);
  registerMetadataTools(server, client);
  registerFileTools(server, client);
  registerGoalTools(server, client);
  registerApplicantTrackingTools(server, client);
  registerBenefitsTools(server, client);
  registerTimeTrackingTools(server, client);
  registerAssessmentTools(server, client);
  registerReportTools(server, client);

  return server;
}
