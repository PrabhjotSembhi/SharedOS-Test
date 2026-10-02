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

// 5. Trusted execution context.
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

// 6. Check which tools Bob's agent can see.
const visible = await kernel.listTools(context);

console.log("\n=== VISIBLE TOOLS ===");

console.log(
  visible.map(({ name }) => name),
);

// 7. Try an allowed search.
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

console.log("\n=== ALLOWED REQUEST ===");

console.log(allowed.status);

// 8. Try searching outside the permitted folder.
const denied = await kernel.invokeTool(context, {
  id: crypto.randomUUID(),

  tool: "files.search",

  arguments: {
    path: ["Work", "Finance"],
    query: "salary",
  },

  traceId: context.traceId,

  requestedAt: new Date().toISOString(),
});

console.log("\n=== UNAUTHORIZED REQUEST ===");

console.log(denied.status);