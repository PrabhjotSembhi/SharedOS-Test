import {
  CapabilityAuthorizer,
  InMemoryGrantUsageStore,
  SharedOSKernel,
  registerStandardOsTools,
} from "@aicoo/sharedos";

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