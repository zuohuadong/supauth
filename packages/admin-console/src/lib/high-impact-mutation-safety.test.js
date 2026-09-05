// @ts-nocheck
import { describe, expect, test } from "bun:test";
import { AdminApiError } from "./admin-api.js";
import {
  completeCursorCollectionItems,
  completeCollectionItems,
  createKeyedSingleFlightTracker,
  mutationOutcomeUnknown,
} from "./resource-page.js";

function deferredRequest() {
  let resolveRequest;
  const promise = new Promise((resolve) => {
    resolveRequest = resolve;
  });
  return { promise, resolve: resolveRequest };
}

function functionBody(source, functionName) {
  const signatureOffset = source.indexOf(`function ${functionName}(`);
  if (signatureOffset < 0) throw new Error(`Missing ${functionName}`);
  const bodyStart = source.indexOf("{", signatureOffset);
  let braceDepth = 0;
  for (let index = bodyStart; index < source.length; index += 1) {
    if (source[index] === "{") braceDepth += 1;
    if (source[index] === "}") braceDepth -= 1;
    if (braceDepth === 0) return source.slice(bodyStart + 1, index);
  }
  throw new Error(`Unclosed ${functionName}`);
}

async function routeSource(relativePath) {
  return Bun.file(new URL(`../routes/${relativePath}`, import.meta.url)).text();
}

function extractedFunction(source, name, parameters) {
  return `function ${name}(${parameters}) {${functionBody(source, name)}}`;
}

function createReplayHandlerHarness(source, scenario) {
  return new Function(
    "completeCursorCollectionItems",
    "deliveryResponses",
    "diagnosticsLoaded",
    "staleAfterWrite",
    `
      let deliveryReadIndex = 0;
      let replayCalls = 0;
      let diagnosticUpdates = [];
      let error = null;
      let mutationStorageReady = true;
      const durableLocks = new Set();
      const webhookOperations = {
        isCurrent: () => !staleAfterWrite,
      };
      function t(message) { return message; }
      function webhookPending() { return false; }
      function diagnosticState() {
        return { last: { id: "delivery-old", success: false } };
      }
      function updateDiagnostic(_whId, update) { diagnosticUpdates.push(update); }
      function replayResourceId(whId, deliveryId) { return whId + ":" + deliveryId; }
      function webhookLockKey(action, resourceId) { return action + ":" + resourceId; }
      function webhookMutationLocked(action, resourceId) {
        return durableLocks.has(webhookLockKey(action, resourceId));
      }
      function stageWebhookMutation(action, resourceId) {
        durableLocks.add(webhookLockKey(action, resourceId));
        return true;
      }
      function recordWebhookMutationUnknown(action, resourceId) {
        durableLocks.add(webhookLockKey(action, resourceId));
        return true;
      }
      function clearWebhookMutationLock(action, resourceId) {
        durableLocks.delete(webhookLockKey(action, resourceId));
        return true;
      }
      function confirm() { return true; }
      function beginWebhookOperation(whId, action, resourceId) {
        return { ownerContext: { action, webhookId: whId, resourceId } };
      }
      function finishWebhookOperation() {}
      async function listWebhookDeliveries() {
        const response = deliveryResponses[deliveryReadIndex++];
        if (response instanceof Error) throw response;
        return response;
      }
      async function replayWebhookDelivery() {
        replayCalls += 1;
        return { id: "delivery-new" };
      }
      async function loadWebhookDiagnostics() { return diagnosticsLoaded; }
      ${extractedFunction(source, "getField", "record, ...keys")}
      ${extractedFunction(source, "deliveryIdentity", "delivery")}
      ${extractedFunction(source, "completeDeliveryList", "response")}
      async function handleReplayLast(whId) {
        ${functionBody(source, "handleReplayLast")}
      }
      return {
        run: handleReplayLast,
        replayCalls: () => replayCalls,
        lockCount: () => durableLocks.size,
        diagnosticUpdates: () => diagnosticUpdates,
        error: () => error,
      };
    `,
  )(
    completeCursorCollectionItems,
    scenario.deliveryResponses,
    scenario.diagnosticsLoaded ?? true,
    scenario.staleAfterWrite ?? false,
  );
}

function cursorDeliveries(items, nextCursor = null, total = items.length) {
  return { items, total, limit: 100, next_cursor: nextCursor };
}

function expectConfirmedBeforeMutation(source, functionName, mutationCall) {
  const body = functionBody(source, functionName);
  const confirmationOffset = body.indexOf("confirm(");
  const beginOffsets = [body.indexOf(".begin("), body.indexOf("beginWebhookOperation(")]
    .filter((offset) => offset >= 0);
  const beginOffset = Math.min(...beginOffsets);
  const operationOffset = body.indexOf(mutationCall);
  expect(confirmationOffset).toBeGreaterThanOrEqual(0);
  expect(beginOffset).toBeGreaterThan(confirmationOffset);
  expect(operationOffset).toBeGreaterThan(beginOffset);
  expect(body.slice(confirmationOffset, beginOffset)).toContain("return");
}

describe("high-impact admin mutation safety", () => {
  test("executes replay only across strict complete cursor envelopes", async () => {
    const source = await routeSource("webhooks/+page.svelte");
    const before = cursorDeliveries([{ id: "delivery-old" }]);
    const after = cursorDeliveries([
      { id: "delivery-old" },
      { id: "delivery-new" },
    ]);

    const successfulReplay = createReplayHandlerHarness(source, {
      deliveryResponses: [before, after],
    });
    await successfulReplay.run("webhook-one");
    expect(successfulReplay.replayCalls()).toBe(1);
    expect(successfulReplay.lockCount()).toBe(0);
    expect(successfulReplay.diagnosticUpdates().at(-1)?.status).toBe(
      "Replay queued",
    );

    for (const rejectedBefore of [
      cursorDeliveries([{ id: "delivery-old" }], "cursor-two", 2),
      { items: [{ id: "delivery-old" }], total: 1, limit: 100 },
    ]) {
      const rejectedReplay = createReplayHandlerHarness(source, {
        deliveryResponses: [rejectedBefore],
      });
      await rejectedReplay.run("webhook-one");
      expect(rejectedReplay.replayCalls()).toBe(0);
      expect(rejectedReplay.lockCount()).toBe(0);
      expect(rejectedReplay.diagnosticUpdates().at(-1)?.status).toMatch(
        /cursor collection/,
      );
    }
  });

  test("keeps replay locked when diagnostics or post-write reads fail", async () => {
    const source = await routeSource("webhooks/+page.svelte");
    const before = cursorDeliveries([{ id: "delivery-old" }]);
    const after = cursorDeliveries([
      { id: "delivery-old" },
      { id: "delivery-new" },
    ]);

    const failedDiagnostics = createReplayHandlerHarness(source, {
      deliveryResponses: [before, after],
      diagnosticsLoaded: false,
    });
    await failedDiagnostics.run("webhook-one");
    expect(failedDiagnostics.replayCalls()).toBe(1);
    expect(failedDiagnostics.lockCount()).toBe(1);
    expect(failedDiagnostics.diagnosticUpdates()).not.toContainEqual(
      expect.objectContaining({ status: "Replay queued" }),
    );

    const failedReadBack = createReplayHandlerHarness(source, {
      deliveryResponses: [before, new Error("delivery read failed")],
    });
    await failedReadBack.run("webhook-one");
    expect(failedReadBack.replayCalls()).toBe(1);
    expect(failedReadBack.lockCount()).toBe(1);
    expect(failedReadBack.diagnosticUpdates().at(-1)?.status).toMatch(
      /read-back failed/,
    );

    const staleReplay = createReplayHandlerHarness(source, {
      deliveryResponses: [before, after],
      staleAfterWrite: true,
    });
    await staleReplay.run("webhook-one");
    expect(staleReplay.replayCalls()).toBe(1);
    expect(staleReplay.lockCount()).toBe(1);
    expect(staleReplay.diagnosticUpdates()).not.toContainEqual(
      expect.objectContaining({ status: "Replay queued" }),
    );
  });

  test("keeps a deferred double click to one request per resource key", async () => {
    const tracker = createKeyedSingleFlightTracker();
    const requestGate = deferredRequest();
    let requestCount = 0;

    async function runReplay() {
      const operation = tracker.begin("webhook-one:delivery-one");
      if (!operation) return false;
      requestCount += 1;
      await requestGate.promise;
      tracker.finish(operation);
      return true;
    }

    const firstReplay = runReplay();
    const secondReplay = runReplay();
    expect(requestCount).toBe(1);
    expect(await secondReplay).toBe(false);
    requestGate.resolve();
    expect(await firstReplay).toBe(true);
  });

  test("places confirmation and its cancel return before every destructive request", async () => {
    const sources = {
      applicationList: await routeSource("applications/+page.svelte"),
      applicationDetail: await routeSource("applications/[appId]/+page.svelte"),
      webhookList: await routeSource("webhooks/+page.svelte"),
      webhookDetail: await routeSource("webhooks/[webhookId]/+page.svelte"),
      resourceDetail: await routeSource("api-resources/[resourceId]/+page.svelte"),
      roleDetail: await routeSource("roles/[roleId]/+page.svelte"),
      organizationDetail: await routeSource("organizations/[orgId]/+page.svelte"),
    };
    const confirmedMutations = [
      [sources.applicationList, "handleRotateSecret", "rotateApplicationSecret("],
      [sources.applicationList, "handleDelete", "deleteApplication("],
      [sources.applicationDetail, "rotateSecret", "rotateApplicationSecret("],
      [sources.applicationDetail, "removeApplication", "deleteApplication("],
      [sources.applicationDetail, "clearSignInOverride", "deleteApplicationSignInExperience("],
      [sources.applicationDetail, "unbindApplication", "deleteApplicationBinding("],
      [sources.webhookList, "handleDelete", "deleteWebhook("],
      [sources.webhookList, "handleRotateSecret", "rotateWebhookSecret("],
      [sources.webhookList, "handleReplayLast", "replayWebhookDelivery("],
      [sources.webhookDetail, "rotateSecret", "rotateWebhookSecret("],
      [sources.webhookDetail, "replayDelivery", "replayWebhookDelivery("],
      [sources.resourceDetail, "deleteScope", "deleteResourceScope("],
      [sources.roleDetail, "deletePermission", "deleteRolePermission("],
      [sources.roleDetail, "revokeAssignment", "revokeRole("],
      [sources.organizationDetail, "removeMember", "removeOrganizationMember("],
      [sources.organizationDetail, "unlinkApplication", "deleteOrganizationApplication("],
    ];

    for (const [source, functionName, mutationCall] of confirmedMutations) {
      expectConfirmedBeforeMutation(source, functionName, mutationCall);
    }
  });

  test("treats commit-timeout and every post-write read-back failure as unknown", async () => {
    expect(
      mutationOutcomeUnknown(
        new AdminApiError("timed out after commit", 0, "request_timeout"),
      ),
    ).toBe(true);

    const handlerContracts = [
      ["applications/+page.svelte", "handleDelete", "readApplicationList(", "recordApplicationMutationUnknown("],
      ["applications/[appId]/+page.svelte", "unbindApplication", "listApplicationBindings(", "recordApplicationMutationUnknown("],
      ["webhooks/+page.svelte", "handleDelete", "readWebhookList(", "recordWebhookMutationUnknown("],
      ["webhooks/[webhookId]/+page.svelte", "replayDelivery", "listWebhookDeliveries(", "recordWebhookMutationUnknown("],
      ["api-resources/[resourceId]/+page.svelte", "deleteScope", "getResource(", "stageScopeDelete("],
      ["roles/[roleId]/+page.svelte", "revokeAssignment", "listRoleAssignments(", "stageRevocation("],
      ["organizations/[orgId]/+page.svelte", "removeMember", "listOrganizationMembers(", "stageRemoval("],
    ];

    for (const [path, functionName, readBackCall, unknownMarker] of handlerContracts) {
      const body = functionBody(await routeSource(path), functionName);
      expect(body).toContain(readBackCall);
      expect(body).toContain(unknownMarker);
      expect(body).toMatch(/MayHaveCommitted|Accepted/);
    }
  });

  test("stages durable locks before the newly guarded high-impact requests", async () => {
    const contracts = [
      ["applications/+page.svelte", "handleCreate", "stageApplicationMutation(", "createApplication("],
      ["applications/+page.svelte", "handleRotateSecret", "stageApplicationMutation(", "rotateApplicationSecret("],
      ["applications/+page.svelte", "handleDelete", "stageApplicationMutation(", "deleteApplication("],
      ["applications/[appId]/+page.svelte", "rotateSecret", "stageApplicationMutation(", "rotateApplicationSecret("],
      ["applications/[appId]/+page.svelte", "removeApplication", "stageApplicationMutation(", "deleteApplication("],
      ["applications/[appId]/+page.svelte", "clearSignInOverride", "stageApplicationMutation(", "deleteApplicationSignInExperience("],
      ["applications/[appId]/+page.svelte", "unbindApplication", "stageApplicationMutation(", "deleteApplicationBinding("],
      ["webhooks/+page.svelte", "handleCreate", "stageWebhookMutation(", "createWebhook("],
      ["webhooks/+page.svelte", "handleDelete", "stageWebhookMutation(", "deleteWebhook("],
      ["webhooks/+page.svelte", "handleToggle", "stageWebhookMutation(", "updateWebhook("],
      ["webhooks/+page.svelte", "handleRotateSecret", "stageWebhookMutation(", "rotateWebhookSecret("],
      ["webhooks/+page.svelte", "handleTest", "stageWebhookMutation(", "testWebhook("],
      ["webhooks/+page.svelte", "handleReplayLast", "stageWebhookMutation(", "replayWebhookDelivery("],
      ["webhooks/[webhookId]/+page.svelte", "rotateSecret", "stageWebhookMutation(", "rotateWebhookSecret("],
      ["webhooks/[webhookId]/+page.svelte", "sendTestWebhook", "stageWebhookMutation(", "testWebhook("],
      ["webhooks/[webhookId]/+page.svelte", "replayDelivery", "stageWebhookMutation(", "replayWebhookDelivery("],
      ["enterprise-sso/+page.svelte", "handleCreate", "stageCreateLock(", "createEnterpriseSSOConfig("],
      ["api-resources/[resourceId]/+page.svelte", "deleteScope", "stageScopeDelete(", "deleteResourceScope("],
      ["roles/[roleId]/+page.svelte", "deletePermission", "stageRevocation(", "deleteRolePermission("],
      ["roles/[roleId]/+page.svelte", "revokeAssignment", "stageRevocation(", "revokeRole("],
      ["organizations/[orgId]/+page.svelte", "removeMember", "stageRemoval(", "removeOrganizationMember("],
      ["organizations/[orgId]/+page.svelte", "unlinkApplication", "stageRemoval(", "deleteOrganizationApplication("],
    ];
    for (const [path, functionName, stageCall, mutationCall] of contracts) {
      const body = functionBody(await routeSource(path), functionName);
      expect(body.indexOf(stageCall)).toBeGreaterThanOrEqual(0);
      expect(body.indexOf(stageCall)).toBeLessThan(body.indexOf(mutationCall));
      expect(body).toContain("mutationStorageReady");
    }
    for (const path of [
      "applications/+page.svelte",
      "applications/[appId]/+page.svelte",
      "webhooks/+page.svelte",
      "webhooks/[webhookId]/+page.svelte",
      "enterprise-sso/+page.svelte",
      "api-resources/[resourceId]/+page.svelte",
      "roles/[roleId]/+page.svelte",
      "organizations/[orgId]/+page.svelte",
    ]) {
      const source = await routeSource(path);
      expect(source).toContain("createDurableMutationLockStore");
      expect(source).toMatch(/restore(?:Application|Webhook)?MutationLocks\(\)/);
      expect(source).toContain("mutationStorageReady = false");
      expect(source).toContain("{#if mutationStorageError}");
    }
  });

  test("fails closed on malformed or incomplete authoritative collections", () => {
    expect(() => completeCollectionItems({ unexpected: [] })).toThrow(
      "unknown collection envelope",
    );
    expect(() =>
      completeCollectionItems({ items: [{ id: "one" }], total: 2, page: 1, limit: 1 }),
    ).toThrow("partial collection");
  });

  test("persists application and replay unknown markers without secrets", async () => {
    const applicationList = await routeSource("applications/+page.svelte");
    const applicationDetail = await routeSource(
      "applications/[appId]/+page.svelte",
    );
    const webhookList = await routeSource("webhooks/+page.svelte");
    const webhookDetail = await routeSource("webhooks/[webhookId]/+page.svelte");
    const applicationStorageKey =
      "supaoauth.admin.application-mutation-locks.v2";
    const webhookStorageKey = "supaoauth.admin.webhook-mutation-locks.v2";

    for (const source of [applicationList, applicationDetail]) {
      expect(source).toContain(applicationStorageKey);
      expect(source).toContain("supaoauth.admin.application-mutation-locks.v1");
      expect(source).toContain("restoreApplicationMutationLocks");
      expect(source).toContain("createDurableMutationLockStore");
      expect(source).not.toContain("function parseApplicationMutationLocks");
    }
    for (const source of [webhookList, webhookDetail]) {
      expect(source).toContain(webhookStorageKey);
      expect(source).toContain("supaoauth.admin.webhook-mutation-locks.v1");
      expect(source).toContain("restoreWebhookMutationLocks");
      expect(source).toContain("createDurableMutationLockStore");
      expect(source).not.toContain("function parseWebhookMutationLocks");
      expect(source).toContain("replayResourceId(");
    }

    const serializedLocks = JSON.stringify({
      '["rotate","applications","application-one"]': {
        action: "rotate",
        ownerId: "applications",
        targetId: "application-one",
        recordedAt: 42,
      },
      '["replay","webhooks","webhook-one:delivery-one"]': {
        action: "replay",
        ownerId: "webhooks",
        targetId: "webhook-one:delivery-one",
        recordedAt: 43,
      },
    });
    const reloadedLocks = JSON.parse(serializedLocks);
    expect(Object.values(reloadedLocks).map((lock) => lock.action)).toEqual([
      "rotate",
      "replay",
    ]);
    expect(serializedLocks).not.toMatch(/secret|payload/i);
  });

  test("reads deliveries before and after webhook sends without inventing idempotency", async () => {
    const webhookList = await routeSource("webhooks/+page.svelte");
    const webhookDetail = await routeSource("webhooks/[webhookId]/+page.svelte");
    const apiClient = await Bun.file(
      new URL("./api/client.js", import.meta.url),
    ).text();

    for (const [source, functionName, mutationCall] of [
      [webhookList, "handleTest", "testWebhook("],
      [webhookDetail, "sendTestWebhook", "testWebhook("],
      [webhookList, "handleReplayLast", "replayWebhookDelivery("],
      [webhookDetail, "replayDelivery", "replayWebhookDelivery("],
    ]) {
      const body = functionBody(source, functionName);
      const mutationOffset = body.indexOf(mutationCall);
      expect(body.indexOf("listWebhookDeliveries(")).toBeLessThan(mutationOffset);
      expect(body.lastIndexOf("listWebhookDeliveries(")).toBeGreaterThan(
        mutationOffset,
      );
      expect(body).toContain("beforeIds");
      expect(body).toContain("recordWebhookMutationUnknown(");
    }
    for (const functionName of [
      "testWebhook",
      "replayWebhookDelivery",
    ]) {
      expect(functionBody(apiClient, functionName)).not.toContain(
        "Idempotency-Key",
      );
    }
  });

  test("requires webhook create and rotation authority to be observable", async () => {
    const webhookList = await routeSource("webhooks/+page.svelte");
    const webhookDetail = await routeSource("webhooks/[webhookId]/+page.svelte");
    const createBody = functionBody(webhookList, "handleCreate");
    expect(createBody.indexOf("beforeIds")).toBeLessThan(
      createBody.indexOf("createWebhook("),
    );
    expect(createBody).toContain("reconciledCreatedWebhook(");
    expect(createBody).toContain("creationInterrupted");

    for (const [source, functionName] of [
      [webhookList, "handleRotateSecret"],
      [webhookDetail, "rotateSecret"],
    ]) {
      const body = functionBody(source, functionName);
      expect(body).toContain("validatedWebhookCommandAck(");
      expect(body).not.toContain("getWebhook(");
    }

    const replayBody = functionBody(webhookList, "handleReplayLast");
    const diagnosticsOffset = replayBody.lastIndexOf(
      "loadWebhookDiagnostics(whId, operation)",
    );
    const clearOffset = replayBody.indexOf(
      'clearWebhookMutationLock("replay", mutationResourceId)',
    );
    expect(diagnosticsOffset).toBeGreaterThanOrEqual(0);
    expect(clearOffset).toBeGreaterThan(diagnosticsOffset);
    expect(replayBody.slice(diagnosticsOffset, clearOffset)).toContain(
      "recordWebhookMutationUnknown",
    );
    expect(replayBody.slice(diagnosticsOffset, clearOffset)).toContain(
      "return",
    );
    expect(replayBody).toContain('status: t("Replay queued")');
  });

  test("keeps storage failure visible while normal loads clear request errors", async () => {
    for (const [path, loadFunction, storageErrorName] of [
      ["applications/+page.svelte", "load", "mutationStorageError"],
      ["applications/[appId]/+page.svelte", "loadApplicationData", "mutationStorageError"],
      ["webhooks/+page.svelte", "load", "mutationStorageError"],
      ["webhooks/[webhookId]/+page.svelte", "loadWebhookData", "mutationStorageError"],
    ]) {
      const source = await routeSource(path);
      expect(functionBody(source, loadFunction)).not.toContain(
        `${storageErrorName} = null`,
      );
      expect(source).toContain(`{#if ${storageErrorName}}`);
    }
  });
});
