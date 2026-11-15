const { sanitizeObservabilityAttributes: sanitizeWithSdk } = require("@agentdid/sdk");

function composeEventHandlers(...handlers) {
  const activeHandlers = handlers.filter(Boolean);

  return (event) => {
    for (const handler of activeHandlers) {
      try {
        handler(event);
      } catch {
        continue;
      }
    }
  };
}

function serializeObservabilityEvent(
  event,
  {
    source = "agent_did_langchain",
    includeTimestamp = true,
    extraFields,
  } = {}
) {
  const record = {
    source,
    eventType: event.eventType,
    level: event.level,
    attributes: sanitizeObservabilityAttributes(event.attributes ?? {}),
  };

  if (includeTimestamp) {
    record.timestamp = new Date().toISOString();
  }

  if (extraFields) {
    Object.assign(record, sanitizeObservabilityAttributes(extraFields));
  }

  return record;
}

function createJsonLoggerEventHandler(
  logger,
  {
    source = "agent_did_langchain",
    includeTimestamp = true,
    extraFields,
  } = {}
) {
  return (event) => {
    const record = serializeObservabilityEvent(event, {
      source,
      includeTimestamp,
      extraFields,
    });
    logWithLogger(logger, event.level, JSON.stringify(record));
  };
}

function createLangSmithRunTree(
  {
    name,
    projectName = "agent-did-langchain",
    runType = "chain",
    inputs,
    tags,
    extra,
    client,
  } = {}
) {
  const RunTree = loadLangSmithRunTree();

  return new RunTree({
    name,
    run_type: runType,
    project_name: projectName,
    inputs: sanitizeObservabilityAttributes(inputs ?? {}),
    tags: [...(tags ?? [])],
    extra: sanitizeObservabilityAttributes(extra ?? {}),
    client,
    serialized: {},
  });
}

function createLangSmithEventHandler(
  runTree,
  {
    source = "agent_did_langchain",
    includeTimestamp = true,
    extraFields,
    tags,
    postImmediately = false,
  } = {}
) {
  const activeToolRuns = new Map();
  const normalizedTags = [...(tags ?? [])];

  return (event) => {
    const record = serializeObservabilityEvent(event, {
      source,
      includeTimestamp,
      extraFields,
    });
    const attributes = record.attributes ?? {};
    const toolName = attributes.tool_name;
    const did = attributes.did;
    const eventType = event.eventType;

    try {
      runTree.addEvent(toLangSmithEvent(record));
    } catch {
      // no-op defensive boundary
    }

    if (isLangSmithToolEvent(toolName, did, eventType)) {
      handleLangSmithToolEvent({
        runTree,
        activeToolRuns,
        normalizedTags,
        source,
        postImmediately,
        toolName,
        did,
        eventType,
        attributes,
        record,
      });
      return;
    }

    handleLangSmithGenericEvent({
      runTree,
      normalizedTags,
      source,
      postImmediately,
      eventType,
      attributes,
      record,
    });
  };
}

function createAgentDidObserver({ eventHandler, logger } = {}) {
  return {
    emit(eventType, { attributes = {}, level = "info" } = {}) {
      const event = {
        eventType,
        level,
        attributes: sanitizeObservabilityAttributes(attributes),
      };

      if (eventHandler) {
        try {
          eventHandler(event);
        } catch {
          // no-op defensive boundary
        }
      }

      if (logger) {
        try {
          logWithLogger(
            logger,
            level,
            `agent_did_langchain event=${event.eventType} attributes=${JSON.stringify(event.attributes)}`
          );
        } catch {
          // no-op defensive boundary
        }
      }
    },
  };
}

/**
 * Redacts sensitive values before events leave the integration boundary. Delegates to the SDK's
 * `sanitizeObservabilityAttributes`, the one sanitizer every integration uses.
 */
function sanitizeObservabilityAttributes(attributes) {
  const sanitized = sanitizeWithSdk(attributes ?? {});
  return sanitized && typeof sanitized === "object" && !Array.isArray(sanitized) ? sanitized : {};
}

function logWithLogger(logger, level, message) {
  const normalizedLevel = normalizeLevel(level);
  if (typeof logger[normalizedLevel] === "function") {
    logger[normalizedLevel](message);
    return;
  }

  if (typeof logger.log === "function") {
    logger.log(normalizedLevel, message);
  }
}

function normalizeLevel(level) {
  if (level === "debug" || level === "warning" || level === "error") {
    return level === "warning" ? "warn" : level;
  }

  return "info";
}

function loadLangSmithRunTree() {
  try {
    const { RunTree } = require("langsmith");
    if (typeof RunTree !== "function") {
      throw new Error("RunTree export not found");
    }
    return RunTree;
  } catch (error) {
    const wrappedError = new Error(
      "LangSmith is required for the LangSmith observability adapter. Install the optional 'langsmith' package to enable it."
    );
    wrappedError.cause = error;
    throw wrappedError;
  }
}

function toLangSmithEvent(record) {
  return {
    name: record.eventType ?? "event",
    kwargs: record,
  };
}

function isLangSmithToolEvent(toolName, did, eventType) {
  return typeof toolName === "string" && typeof did === "string" && eventType.startsWith("agent_did.tool.");
}

function createLangSmithChildRun(runTree, { name, runType, inputs, tags, source, eventType }) {
  return runTree.createChild({
    name,
    run_type: runType,
    inputs,
    tags,
    extra: { source, agent_did_event_type: eventType },
    serialized: {},
  });
}

function handleLangSmithToolEvent({
  runTree,
  activeToolRuns,
  normalizedTags,
  source,
  postImmediately,
  toolName,
  did,
  eventType,
  attributes,
  record,
}) {
  const runKey = `${toolName}:${did}`;
  let childRun = activeToolRuns.get(runKey);

  if (eventType.endsWith(".started")) {
    childRun = createLangSmithChildRun(runTree, {
      name: toolName,
      runType: "tool",
      inputs: { did, inputs: attributes.inputs ?? {}, event_type: eventType },
      tags: [...normalizedTags, "agent-did", "tool"],
      source,
      eventType,
    });
    childRun.addEvent(toLangSmithEvent(record));
    activeToolRuns.set(runKey, childRun);
    maybePostLangSmithRun(childRun, { postImmediately, finalized: false });
    return;
  }

  if (!childRun) {
    childRun = createLangSmithChildRun(runTree, {
      name: toolName,
      runType: "tool",
      inputs: { did, event_type: eventType },
      tags: [...normalizedTags, "agent-did", "tool"],
      source,
      eventType,
    });
  }

  childRun.addEvent(toLangSmithEvent(record));

  if (eventType.endsWith(".failed")) {
    void childRun.end(
      { did, event_type: eventType, attributes },
      String(attributes.error ?? "unknown error")
    );
  } else {
    void childRun.end({ did, event_type: eventType, attributes });
  }

  activeToolRuns.delete(runKey);
  maybePostLangSmithRun(childRun, { postImmediately, finalized: true });
}

function handleLangSmithGenericEvent({
  runTree,
  normalizedTags,
  source,
  postImmediately,
  eventType,
  attributes,
  record,
}) {
  const childRun = createLangSmithChildRun(runTree, {
    name: eventType,
    runType: "chain",
    inputs: { event_type: eventType, attributes },
    tags: [...normalizedTags, "agent-did", "event"],
    source,
    eventType,
  });

  childRun.addEvent(toLangSmithEvent(record));
  void childRun.end({ event_type: eventType, attributes });
  maybePostLangSmithRun(childRun, { postImmediately, finalized: true });
}

const postedRuns = new WeakSet();

function maybePostLangSmithRun(runTree, { postImmediately, finalized }) {
  if (!postImmediately) {
    return;
  }

  void Promise.resolve().then(async () => {
    try {
      if (!postedRuns.has(runTree) && typeof runTree.postRun === "function") {
        postedRuns.add(runTree);
        await runTree.postRun();
      }

      if (finalized && typeof runTree.patchRun === "function") {
        await runTree.patchRun();
      }
    } catch {
      // no-op defensive boundary
    }
  });
}

module.exports = {
  composeEventHandlers,
  createAgentDidObserver,
  createJsonLoggerEventHandler,
  createLangSmithEventHandler,
  createLangSmithRunTree,
  sanitizeObservabilityAttributes,
  serializeObservabilityEvent,
};