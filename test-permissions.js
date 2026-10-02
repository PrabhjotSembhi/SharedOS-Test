import {
  CapabilityAuthorizer,
  InMemoryGrantUsageStore,
  SharedOSKernel,
  registerStandardOsTools,
} from "@aicoo/sharedos";

import {
  deriveGrant,
} from "@aicoo/sharedos-core";

const alice = {
  kind: "human",
  userId: "alice",
};

const bobAgent = {
  kind: "agent",
  agentId: "bob-assistant",
};

// 1. Fake file storage.
// In a real application this would connect to your database/filesystem.
const files = {
  namespace: "files",

  async invoke(operation, signal) {
    signal.throwIfAborted();

    return {
      operationId: operation.operationId,
      completedAt: new Date().toISOString(),
      status: "succeeded",

      output: {
        hits: [
          {
            text: "Atlas ships 2026-09-30.",
          },
        ],
      },
    };
  },
};

// 2. Give Bob's agent permission to search ONLY this folder.
const grant = {
  id: "grant-1",

  namespaceId: "acme",

  subject: bobAgent,

  issuer: alice,

  capabilities: [
    {
      resource: {
        namespace: "files",
        path: ["Work", "Projects", "atlas"],
        owner: alice,
      },

      actions: ["search"],

      scope: "descendants",
    },
  ],

  constraints: {
    purposes: ["atlas-status"],

    expiresAt: new Date(
      Date.now() + 3_600_000,
    ).toISOString(),

    maxUses: 3,
  },

  issuedAt: new Date().toISOString(),
};

// 3. Our trusted grant store.
const issued = [grant];

// 4. Create SharedOS.
const authorizer = new CapabilityAuthorizer({
  usageStore: new InMemoryGrantUsageStore(),
});

const kernel = new SharedOSKernel({
  grantSource: {
    async load(access) {
      return issued.filter(
        (candidate) =>
          candidate.namespaceId === access.namespaceId &&
          JSON.stringify(candidate.subject) ===
            JSON.stringify(access.actor) &&
          JSON.stringify(candidate.issuer) ===
            JSON.stringify(access.authority),
      );
    },
  },

  authorizer,
});

// Register our file provider.
kernel.registerResourceProvider(files);

// Register SharedOS's standard file tools.
registerStandardOsTools(kernel, { files });

const context = {
  namespaceId: "acme",

  actor: bobAgent,

  authority: alice,

  owner: alice,

  purpose: "atlas-status",

  traceId: crypto.randomUUID(),

  enabledToolNamespaces: ["files"],

  now: new Date().toISOString(),
};

// --------------------------------------------------
// TEST 1: Allowed resource
// --------------------------------------------------

const allowed = await kernel.invokeTool(context, {
  id: crypto.randomUUID(),

  tool: "files.search",

  arguments: {
    path: ["Work", "Projects", "atlas"],
    query: "ship date",
  },

  traceId: context.traceId,

  requestedAt: new Date().toISOString(),
});

console.log("\nTEST 1 — Allowed resource");

console.log("Expected: succeeded");
console.log("Actual:  ", allowed.status);

console.log(
  allowed.status === "succeeded" ? "PASS" : "FAIL",
);


// --------------------------------------------------
// TEST 2: Unauthorized resource
// --------------------------------------------------

const unauthorized = await kernel.invokeTool(context, {
  id: crypto.randomUUID(),

  tool: "files.search",

  arguments: {
    path: ["Work", "Finance"],
    query: "salary",
  },

  traceId: context.traceId,

  requestedAt: new Date().toISOString(),
});

console.log("\nTEST 2 — Unauthorized resource");

console.log("Expected: denied");
console.log("Actual:  ", unauthorized.status);

console.log(
  unauthorized.status === "denied" ? "PASS" : "FAIL",
);
// --------------------------------------------------
// TEST 3: Path traversal attempt
// --------------------------------------------------

const traversal = await kernel.invokeTool(context, {
  id: crypto.randomUUID(),

  tool: "files.search",

  arguments: {
    path: ["Work", "Projects", "atlas", "..", "..", "Finance"],
    query: "salary",
  },

  traceId: context.traceId,

  requestedAt: new Date().toISOString(),
});

console.log("\nTEST 3 — Path traversal");

console.log("Expected: failed / invalid_tool_arguments");

console.log(
  "Actual:",
  traversal.status,
  traversal.error?.code,
);

const passed =
  traversal.status === "failed" &&
  traversal.error?.code === "invalid_tool_arguments";

console.log(passed ? "PASS" : "FAIL");



// --------------------------------------------------
// TEST 4: Action escalation
// Same authorized path, unauthorized action
// --------------------------------------------------

const actionEscalation = await kernel.invokeTool(context, {
  id: crypto.randomUUID(),

  tool: "files.create",

  arguments: {
    path: ["Work", "Projects", "atlas", "malicious.txt"],
    content: "This should never be created.",
  },

  traceId: context.traceId,

  requestedAt: new Date().toISOString(),
});

console.log("\nTEST 4 — Unauthorized action");

console.log("Expected: denied");

console.log(
  "Actual:",
  actionEscalation.status,
  actionEscalation.error?.code ?? "",
);

const actionPassed =
  actionEscalation.status === "denied";

console.log(actionPassed ? "PASS" : "FAIL");


// --------------------------------------------------
// TEST 5: Effective tool catalogue
// --------------------------------------------------

const visibleTools = await kernel.listTools(context);

const toolNames = visibleTools.map(({ name }) => name);

console.log("\nTEST 5 — Effective tool catalogue");

console.log("Visible tools:", toolNames);

const searchVisible = toolNames.includes("files.search");
const createHidden = !toolNames.includes("files.create");

const cataloguePassed =
  searchVisible && createHidden;

console.log("Expected: files.search visible");
console.log("Expected: files.create hidden");

console.log(
  cataloguePassed ? "PASS" : "FAIL",
);


// --------------------------------------------------
// TEST 6: Expired grant
// --------------------------------------------------

const expiredGrant = {
  ...grant,

  id: "expired-grant",

  constraints: {
    ...grant.constraints,

    expiresAt: new Date(Date.now() - 1000).toISOString(),
  },
};

const expiredKernel = new SharedOSKernel({
  grantSource: {
    async load(access) {
      return [expiredGrant].filter(
        (candidate) =>
          candidate.namespaceId === access.namespaceId &&
          JSON.stringify(candidate.subject) ===
            JSON.stringify(access.actor) &&
          JSON.stringify(candidate.issuer) ===
            JSON.stringify(access.authority),
      );
    },
  },

  authorizer: new CapabilityAuthorizer({
    usageStore: new InMemoryGrantUsageStore(),
  }),
});

expiredKernel.registerResourceProvider(files);

registerStandardOsTools(expiredKernel, { files });

const expiredResult = await expiredKernel.invokeTool(context, {
  id: crypto.randomUUID(),

  tool: "files.search",

  arguments: {
    path: ["Work", "Projects", "atlas"],
    query: "ship date",
  },

  traceId: context.traceId,

  requestedAt: new Date().toISOString(),
});

console.log("\nTEST 6 — Expired grant");

console.log("Expected: denied");

console.log(
  "Actual:",
  expiredResult.status,
  expiredResult.error?.code ?? "",
);

console.log(
  expiredResult.status === "denied"
    ? "PASS"
    : "FAIL",
);



// --------------------------------------------------
// TEST 7: maxUses enforcement
// --------------------------------------------------

console.log("\nTEST 7 — maxUses enforcement");

console.log("\nGrant maxUses:", grant.constraints.maxUses);
for (let i = 1; i <= 3; i++) {

  const result = await kernel.invokeTool(context, {
    id: crypto.randomUUID(),

    tool: "files.search",

    arguments: {
      path: ["Work", "Projects", "atlas"],
      query: "ship date",
    },

    traceId: context.traceId,

    requestedAt: new Date().toISOString(),
  });

  console.log(
    `Call ${i}:`,
    result.status,
    result.error?.code ?? "",
  );
}


// --------------------------------------------------
// TEST 8: Grant isolation between agents
// --------------------------------------------------

const charlieAgent = {
  kind: "agent",
  agentId: "charlie-assistant",
};

const charlieContext = {
  ...context,

  actor: charlieAgent,

  traceId: crypto.randomUUID(),
};

const charlieResult = await kernel.invokeTool(
  charlieContext,
  {
    id: crypto.randomUUID(),

    tool: "files.search",

    arguments: {
      path: ["Work", "Projects", "atlas"],
      query: "ship date",
    },

    traceId: charlieContext.traceId,

    requestedAt: new Date().toISOString(),
  },
);

console.log("\nTEST 8 — Agent grant isolation");

console.log("Expected: denied");

console.log(
  "Actual:",
  charlieResult.status,
  charlieResult.error?.code ?? "",
);

console.log(
  charlieResult.status === "denied"
    ? "PASS"
    : "FAIL",
);


// --------------------------------------------------
// TEST 9: Delete without grant
// --------------------------------------------------

const deleteAttempt = await kernel.invokeTool(context, {
  id: crypto.randomUUID(),

  tool: "files.delete",

  arguments: {
    path: ["Work", "Projects", "atlas", "important.txt"],
  },

  traceId: context.traceId,

  requestedAt: new Date().toISOString(),
});

console.log("\nTEST 9 — Delete without grant");

console.log("Expected: denied");

console.log(
  "Actual:",
  deleteAttempt.status,
  deleteAttempt.error?.code ?? "",
);

console.log(
  deleteAttempt.status === "denied"
    ? "PASS"
    : "FAIL",
);



// --------------------------------------------------
// TEST 10: Delegation cannot escalate authority
// --------------------------------------------------
console.log("Parent constraints:", grant.constraints);
// --------------------------------------------------
// TEST 10: Delegation cannot escalate authority
// --------------------------------------------------

const delegationParents = {
  id: crypto.randomUUID(),

  namespaceId: "acme",

  subject: {
    kind: "agent",
    agentId: "bob-assistant",
  },

  issuer: {
    kind: "user",
    userId: "alice",
  },

  capabilities: [
    {
      resource: {
        namespace: "acme",
        owner: context.owner,
        path: ["Work", "Projects", "atlas"],
      },
      scope: "exact",
      actions: ["search"],
    },
  ],

  constraints: {
    purposes: ["atlas-status"],
    delegationDepth: 1,
  },

  issuedAt: new Date().toISOString(),
};

const delegationAttempt = deriveGrant(delegationParents, {
  id: crypto.randomUUID(),

  subject: {
    kind: "agent",
    agentId: "charlie-assistant",
  },

  capabilities: [
    {
      resource: {
        namespace: "acme",
        owner: context.owner,
        path: ["Work", "Projects", "atlas"],
      },
      scope: "exact",
      actions: ["delete"],
    },
  ],

  issuedAt: new Date().toISOString(),
});

console.log("\nTEST 10 — Delegation cannot escalate authority");

console.log("Expected: rejected");

console.log(
  "Actual:",
  delegationAttempt.ok
    ? "accepted"
    : `rejected ${delegationAttempt.reason}`,
);

console.log(
  !delegationAttempt.ok &&
  delegationAttempt.reason === "capability_not_within_parent"
    ? "PASS"
    : "FAIL",
);

grant.revokedAt = new Date().toISOString();
// --------------------------------------------------
// TEST 11: Revoked grant
// --------------------------------------------------

grant.revokedAt = new Date().toISOString();

const revoked = await kernel.invokeTool(context, {
  id: crypto.randomUUID(),

  tool: "files.search",

  arguments: {
    path: ["Work", "Projects", "atlas"],
    query: "ship date",
  },

  traceId: context.traceId,

  requestedAt: new Date().toISOString(),
});

console.log("\nTEST 11 — Revoked grant");

console.log("Expected: denied");

console.log(
  "Actual:",
  revoked.status,
  revoked.error?.code ?? "",
);

console.log(
  revoked.status === "denied"
    ? "PASS"
    : "FAIL",
);



// --------------------------------------------------
// TEST 12: Cross-namespace access
// --------------------------------------------------

const otherTenantContext = {
  ...context,
  namespaceId: "other-company",
};

const crossNamespace = await kernel.invokeTool(otherTenantContext, {
  id: crypto.randomUUID(),

  tool: "files.search",

  arguments: {
    path: ["Work", "Projects", "atlas"],
    query: "ship date",
  },

  traceId: otherTenantContext.traceId,

  requestedAt: new Date().toISOString(),
});

console.log("\nTEST 12 — Cross-namespace access");

console.log("Expected: denied");

console.log(
  "Actual:",
  crossNamespace.status,
  crossNamespace.error?.code ?? "",
);

console.log(
  crossNamespace.status === "denied"
    ? "PASS"
    : "FAIL",
);



// --------------------------------------------------
// TEST 13: Delegation depth cannot be exceeded
// --------------------------------------------------

const delegationParent = {
  ...grant,

  id: "delegation-parent",

  // Remove maxUses because bounded parents cannot be delegated.
  constraints: {
    purposes: ["atlas-status"],
    expiresAt: new Date(
      Date.now() + 3_600_000,
    ).toISOString(),
    delegationDepth: 1,
  },
};

const childResult = deriveGrant(delegationParent, {
  id: "delegation-child",

  subject: {
    kind: "agent",
    agentId: "child-agent",
  },

  capabilities: delegationParent.capabilities,

  constraints: {
    delegationDepth: 0,
  },

  issuedAt: new Date().toISOString(),
});

console.log("\nTEST 13 — Delegation depth");

console.log(
  "Parent delegationDepth:",
  delegationParent.constraints.delegationDepth,
);

console.log(
  "Child creation:",
  childResult.ok
    ? "succeeded"
    : `rejected ${childResult.reason}`,
);

// Now try to delegate AGAIN from the child.
let grandchildResult;

if (childResult.ok) {
  grandchildResult = deriveGrant(childResult.grant, {
    id: "delegation-grandchild",

    subject: {
      kind: "agent",
      agentId: "grandchild-agent",
    },

    capabilities: childResult.grant.capabilities,

    constraints: {
      delegationDepth: 0,
    },

    issuedAt: new Date().toISOString(),
  });
}

console.log(
  "Grandchild creation:",
  grandchildResult?.ok
    ? "succeeded"
    : `rejected ${grandchildResult?.reason ?? "not attempted"}`,
);

console.log(
  grandchildResult?.ok === false
    ? "PASS"
    : "FAIL",
);




// --------------------------------------------------
// TEST 14 — MCP published tool catalogue


const visibleTools2 = await kernel.listTools(context);

console.log("\nDEBUG — listTools()");
console.log(
  visibleTools2.map((tool) => ({
    name: tool.name,
    namespace: tool.namespace,
    requiredCapability: tool.requiredCapability,
  })),
);










// --------------------------------------------------

const mcpCatalog = await kernel.listPublishedTools(context, {
  executionId: crypto.randomUUID(),
});

const mcpToolNames = mcpCatalog.tools.map((tool) => tool.name);

console.log("\nTEST 14 — MCP published tool catalogue");
console.log("Visible MCP tools:", mcpToolNames);

console.log("Expected: files.search visible");
console.log("Expected: unauthorized tools hidden");

console.log(
  mcpToolNames.includes("files.search") &&
  !mcpToolNames.includes("files.create")
    ? "PASS"
    : "FAIL",
);