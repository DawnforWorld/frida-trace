'use strict';

const state = {
  moduleName: null,
  startModuleName: null,
  stopModuleName: null,
  module: null,
  moduleBase: null,
  moduleEnd: null,
  startAddress: null,
  endAddress: null,
  startRva: 0,
  endRva: 0,
  startModule: null,
  stopModule: null,
  startModuleEnd: null,
  stopModuleEnd: null,
  targetOnly: true,
  threadId: null,
  gateAddress: null,
  gateListener: null,
  exitListener: null,
  excludeNonTargetModules: true,
  deferExclusions: false,
  flushEvery: 256,
  followed: {},
  observer: null,
  moduleObserver: null,
  excludedModules: {},
  exportMaps: {},
  externalTargets: {},
  preRecordingBlockStarts: [],
  preRecordingBlockMap: {},
  ready: false,
  recording: false,
  recordThreadId: null,
  done: false,
  count: 0,
  buffer: [],
  pendingRegisters: {}
};

const registerIndexes = {
  rax: 0, rbx: 1, rcx: 2, rdx: 3, rsi: 4, rdi: 5, rbp: 6, rsp: 7,
  r8: 8, r9: 9, r10: 10, r11: 11, r12: 12, r13: 13, r14: 14, r15: 15,
  rflags: 16
};

const registerAliases = {
  al: 'rax', ah: 'rax', ax: 'rax', eax: 'rax',
  bl: 'rbx', bh: 'rbx', bx: 'rbx', ebx: 'rbx',
  cl: 'rcx', ch: 'rcx', cx: 'rcx', ecx: 'rcx',
  dl: 'rdx', dh: 'rdx', dx: 'rdx', edx: 'rdx',
  sil: 'rsi', si: 'rsi', esi: 'rsi', dil: 'rdi', di: 'rdi', edi: 'rdi',
  bpl: 'rbp', bp: 'rbp', ebp: 'rbp', spl: 'rsp', sp: 'rsp', esp: 'rsp',
  r8b: 'r8', r8w: 'r8', r8d: 'r8', r9b: 'r9', r9w: 'r9', r9d: 'r9',
  r10b: 'r10', r10w: 'r10', r10d: 'r10', r11b: 'r11', r11w: 'r11', r11d: 'r11',
  r12b: 'r12', r12w: 'r12', r12d: 'r12', r13b: 'r13', r13w: 'r13', r13d: 'r13',
  r14b: 'r14', r14w: 'r14', r14d: 'r14', r15b: 'r15', r15w: 'r15', r15d: 'r15',
  eflags: 'rflags', flags: 'rflags'
};

function hex(value) {
  return '0x' + value.toString(16);
}

function ptrHex(value) {
  return value.toString();
}

function instructionBytes(address, size) {
  const bytes = new Uint8Array(address.readByteArray(size));
  const parts = [];
  for (const value of bytes) {
    parts.push(value.toString(16).padStart(2, '0'));
  }
  return parts.join(' ');
}

function sameName(a, b) {
  return a.toLowerCase() === b.toLowerCase();
}

function moduleMatchesRequest(module, request) {
  const wanted = request.toLowerCase().replaceAll('/', '\\');
  if (wanted.includes('\\')) {
    return module.path.toLowerCase().replaceAll('/', '\\') === wanted;
  }
  return module.name.toLowerCase() === wanted;
}

function findModuleByRequest(name) {
  const modules = Process.enumerateModules();
  for (const m of modules) {
    if (moduleMatchesRequest(m, name)) {
      return m;
    }
  }
  return null;
}

function addressRva(address, imageBase) {
  return ptrHex(address.sub(imageBase || state.moduleBase));
}

function isTargetAddress(address) {
  return address.compare(state.moduleBase) >= 0 && address.compare(state.moduleEnd) < 0;
}

function moduleContains(module, address) {
  return module !== null && address.compare(module.base) >= 0 &&
    address.compare(module.base.add(module.size)) < 0;
}

function isStartAddress(address) {
  if (state.startModule === null) return false;
  if (state.startRva === 0) return moduleContains(state.startModule, address);
  return address.compare(state.startAddress) === 0;
}

function isStopAddress(address) {
  return state.endRva !== 0 && state.endAddress !== null &&
    address.compare(state.endAddress) === 0;
}

function shouldRecordAddress(address) {
  return !state.targetOnly || isTargetAddress(address) ||
    isStartAddress(address) || isStopAddress(address);
}

function moduleForAddress(address) {
  const module = Process.findModuleByAddress(address);
  if (module === null) {
    return { name: '<anonymous>', base: ptr(0), size: 0 };
  }
  return module;
}

function fullRegisterName(name) {
  const lower = name.toLowerCase();
  if (registerIndexes[lower] !== undefined) {
    return lower;
  }
  return registerAliases[lower] || null;
}

function accessFlags(access) {
  if (typeof access === 'number') {
    return access & 3;
  }
  if (typeof access !== 'string') {
    return 0;
  }
  let flags = 0;
  if (access.includes('r')) flags |= 1;
  if (access.includes('w')) flags |= 2;
  return flags;
}

function addRegisterMask(mask, name) {
  const full = fullRegisterName(name);
  if (full === null) return mask;
  return mask | (1 << registerIndexes[full]);
}

function describeInstructionState(instruction) {
  let readMask = 0;
  let writeMask = 0;
  for (const name of instruction.regsRead || []) readMask = addRegisterMask(readMask, name);
  for (const name of instruction.regsWritten || []) writeMask = addRegisterMask(writeMask, name);

  const memory = [];
  for (const operand of instruction.operands || []) {
    const flags = accessFlags(operand.access);
    if (operand.type === 'reg') {
      if ((flags & 1) !== 0) readMask = addRegisterMask(readMask, operand.value);
      if ((flags & 2) !== 0) writeMask = addRegisterMask(writeMask, operand.value);
      continue;
    }
    if (operand.type !== 'mem') continue;

    const value = normalizeMemoryOperand(operand.value);
    if (value.base !== null && value.base !== 'rip' && value.base !== 'eip') {
      readMask = addRegisterMask(readMask, value.base);
    }
    if (value.index !== null) readMask = addRegisterMask(readMask, value.index);
    if (instruction.mnemonic.toLowerCase() !== 'lea' && memory.length < 4) {
      memory.push({
        size: operand.size || 0,
        flags: flags === 0 ? 1 : flags,
        value,
        nextAddress: instruction.next.toString()
      });
    }
  }
  return { readMask: readMask >>> 0, writeMask: writeMask >>> 0, memory };
}

function memoryEffectiveAddress(description, context) {
  const memory = description.value;
  let address = ptr(0);
  if (memory.base !== null) {
    if (memory.base === 'rip' || memory.base === 'eip') {
      address = ptr(description.nextAddress);
    } else if (context[memory.base] !== undefined) {
      address = context[memory.base];
    } else {
      return ptr(0);
    }
  }
  if (memory.index !== null) {
    const index = context[memory.index];
    if (index === undefined) return ptr(0);
    const scaled = scaledIndex(index, memory.scale);
    if (scaled === null) return ptr(0);
    address = address.add(scaled);
  }
  return address.add(memory.disp);
}

function flush(force) {
  if (state.buffer.length === 0) {
    return;
  }

  let flushCount = state.buffer.length;
  if (force !== true) {
    for (const pending of Object.values(state.pendingRegisters)) {
      const index = state.buffer.indexOf(pending.row);
      if (index >= 0 && index < flushCount) {
        flushCount = index;
      }
    }
  }
  if (flushCount === 0) {
    return;
  }

  send({ type: 'trace', items: state.buffer.slice(0, flushCount) });
  state.buffer = state.buffer.slice(flushCount);
}

function stopFollowing() {
  for (const tidText of Object.keys(state.followed)) {
    const tid = parseInt(tidText, 10);
    try {
      Stalker.unfollow(tid);
    } catch (_) {
    }
  }
  try {
    Stalker.flush();
  } catch (_) {
  }
}

function shouldFollowThread(thread) {
  return state.threadId === null || thread.id === state.threadId;
}

function normalizeMemoryOperand(value) {
  return {
    base: value.base || null,
    index: value.index || null,
    scale: value.scale || 1,
    disp: value.disp || 0
  };
}

function describeTransfer(instruction) {
  const mnemonic = instruction.mnemonic.toLowerCase();
  if (mnemonic === 'ret' || mnemonic === 'retn' || mnemonic === 'retf') {
    return { kind: 'ret' };
  }
  if (mnemonic !== 'call' && mnemonic !== 'jmp') {
    return null;
  }

  const operands = instruction.operands;
  if (operands.length === 0) {
    return null;
  }

  const operand = operands[0];
  if (operand.type === 'imm') {
    return { kind: 'immediate', target: ptr(operand.value).toString() };
  }
  if (operand.type === 'reg') {
    return { kind: 'register', register: operand.value };
  }
  if (operand.type === 'mem') {
    return {
      kind: 'memory',
      memory: normalizeMemoryOperand(operand.value),
      nextAddress: instruction.address.add(instruction.size).toString()
    };
  }
  return null;
}

function scaledIndex(value, scale) {
  if (scale === 1) {
    return value;
  }
  if (scale === 2) {
    return value.shl(1);
  }
  if (scale === 4) {
    return value.shl(2);
  }
  if (scale === 8) {
    return value.shl(3);
  }
  return null;
}

function transferTarget(transfer, context) {
  if (transfer === null) {
    return null;
  }
  if (transfer.kind === 'immediate') {
    return ptr(transfer.target);
  }
  if (transfer.kind === 'ret') {
    const stackPointer = context.rsp || context.esp;
    if (stackPointer !== undefined) {
      return stackPointer.readPointer();
    }
    return context.lr === undefined ? null : context.lr;
  }
  if (transfer.kind === 'register') {
    return context[transfer.register] || null;
  }
  if (transfer.kind !== 'memory') {
    return null;
  }

  const memory = transfer.memory;
  let address = ptr(0);
  if (memory.base !== null) {
    if (memory.base === 'rip' || memory.base === 'eip') {
      address = ptr(transfer.nextAddress);
    } else if (context[memory.base] !== undefined) {
      address = context[memory.base];
    } else {
      return null;
    }
  }
  if (memory.index !== null) {
    const index = context[memory.index];
    if (index === undefined) {
      return null;
    }
    const scaled = scaledIndex(index, memory.scale);
    if (scaled === null) {
      return null;
    }
    address = address.add(scaled);
  }
  address = address.add(memory.disp);
  return address.readPointer();
}

function exportsByAddress(module) {
  const key = moduleKey(module);
  if (state.exportMaps[key] !== undefined) {
    return state.exportMaps[key];
  }

  const exports = {};
  try {
    for (const item of module.enumerateExports()) {
      if (item.type === 'function') {
        exports[ptrHex(item.address)] = item.name;
      }
    }
  } catch (_) {
  }
  state.exportMaps[key] = exports;
  return exports;
}

function externalTargetName(target) {
  return externalTargetNameFrom(target, state.module);
}

function externalTargetNameFrom(target, sourceModule) {
  if (target === null || moduleContains(sourceModule, target)) {
    return null;
  }

  const key = ptrHex(target);
  if (Object.prototype.hasOwnProperty.call(state.externalTargets, key)) {
    return state.externalTargets[key];
  }

  const module = Process.findModuleByAddress(target);
  if (module === null) {
    state.externalTargets[key] = null;
    return null;
  }

  let name = exportsByAddress(module)[key] || null;
  if (name === null) {
    try {
      const symbol = DebugSymbol.fromAddress(target);
      if (symbol !== null && symbol.name !== null && symbol.name !== key) {
        name = symbol.name;
      }
    } catch (_) {
    }
  }

  const result = name === null ? null : module.name.toLowerCase() + '.' + name;
  state.externalTargets[key] = result;
  return result;
}

function putTraceCallout(iterator, instruction, blockStart) {
  const address = instruction.address;
  const size = instruction.size;
  const mnemonic = instruction.mnemonic;
  const opStr = instruction.opStr;
  const text = (mnemonic + ' ' + opStr).trim();
  const bytes = instructionBytes(address, size);
  const transfer = describeTransfer(instruction);
  const instructionState = describeInstructionState(instruction);
  const sourceModule = moduleForAddress(address);
  const groups = instruction.groups;
  const observeAfter = state.endRva !== 0 && address.compare(state.endAddress) === 0 &&
    !groups.includes('call') && !groups.includes('jump') && !groups.includes('ret');

  iterator.putCallout(function (context) {
    onInstruction(address, size, bytes, text, transfer, instructionState, sourceModule,
      blockStart, observeAfter, context);
  });
  return observeAfter;
}

function rememberPreRecordingBlock(blockStart) {
  const key = ptrHex(blockStart);
  if (state.preRecordingBlockMap[key]) {
    return;
  }

  state.preRecordingBlockMap[key] = true;
  state.preRecordingBlockStarts.push(blockStart);
}

function invalidatePreRecordingBlocks() {
  const tids = Object.keys(state.followed);
  if (tids.length === 0 || state.preRecordingBlockStarts.length === 0) {
    return;
  }

  for (const tidText of tids) {
    const tid = parseInt(tidText, 10);
    for (const blockStart of state.preRecordingBlockStarts) {
      try {
        Stalker.invalidate(tid, blockStart);
      } catch (_) {
      }
    }
  }

  send({ type: 'invalidated-pre-recording-blocks', count: state.preRecordingBlockStarts.length });
  state.preRecordingBlockStarts = [];
  state.preRecordingBlockMap = {};
}

function followThread(thread, fromCurrentThread) {
  if (!state.ready || state.done || !shouldFollowThread(thread)) {
    return;
  }

  const tid = thread.id;
  if (state.followed[tid]) {
    return;
  }

  try {
    const options = {
      transform(iterator) {
        let instruction = iterator.next();
        if (instruction === null) {
          return;
        }

        const blockStart = instruction.address;
        let sawTargetInstruction = false;
        let emitCallouts = state.recording;

        while (instruction !== null) {
          const address = instruction.address;

          const startHere = isStartAddress(address);
          const recordHere = shouldRecordAddress(address);
          if (recordHere) {
            sawTargetInstruction = true;

            if (state.deferExclusions && isTargetAddress(address)) {
              iterator.putCallout(function () {
                activateDeferredExclusions();
              });
            }

            if (!emitCallouts && startHere) {
              emitCallouts = true;
            }

            let observeAfter = false;
            if (emitCallouts) {
              observeAfter = putTraceCallout(iterator, instruction, blockStart);
            }

            iterator.keep();
            if (observeAfter) {
              const completedAddress = address;
              iterator.putCallout(function (context) {
                onEndInstructionComplete(completedAddress, context);
              });
            }
          } else {
            iterator.keep();
          }
          instruction = iterator.next();
        }

        if (sawTargetInstruction && !state.recording) {
          rememberPreRecordingBlock(blockStart);
        }
      }
    };

    if (fromCurrentThread === true) {
      Stalker.follow(options);
    } else {
      Stalker.follow(tid, options);
    }

    state.followed[tid] = true;
    send({ type: 'stalking-thread', threadId: tid });
  } catch (e) {
    send({ type: 'agent-error', message: 'failed to stalk thread ' + tid + ': ' + e.message });
  }
}

function activateDeferredExclusions() {
  if (!state.deferExclusions) {
    return;
  }

  state.deferExclusions = false;
  state.excludeNonTargetModules = true;
  excludeNonTargetModules();
  send({ type: 'non-target-exclusions-activated' });
}

function followExistingThreads() {
  const threads = Process.enumerateThreads();
  for (const thread of threads) {
    followThread(thread);
  }
}

function installStalkerGate() {
  if (state.gateAddress === null || state.gateListener !== null) {
    return;
  }

  state.gateListener = Interceptor.attach(state.gateAddress, {
    onEnter() {
      const tid = currentThreadId();
      if (state.threadId !== null && tid !== state.threadId) {
        return;
      }

      const listener = state.gateListener;
      state.gateListener = null;
      if (listener !== null) {
        listener.detach();
      }
      followThread({ id: tid }, true);
      send({ type: 'stalker-gate-hit', threadId: tid, address: ptrHex(state.gateAddress) });
    }
  });
  Interceptor.flush();
  send({ type: 'stalker-gate-ready', address: ptrHex(state.gateAddress) });
}

function installExitListener() {
  if (state.endRva !== 0 || state.exitListener !== null) return;
  try {
    const exitAddress = Module.getGlobalExportByName('RtlExitUserProcess');
    state.exitListener = Interceptor.attach(exitAddress, {
      onEnter() {
        if (!state.recording || state.done) return;
        const tid = currentThreadId();
        completePreviousInstruction(tid, snapshotRegisters(this.context));
        finishTrace(tid, exitAddress, 'process-exit');
      }
    });
  } catch (e) {
    send({ type: 'agent-error', message: 'failed to install process-exit listener: ' + e.message });
  }
}

function startThreadObserver() {
  if (state.observer !== null) {
    return;
  }

  state.observer = Process.attachThreadObserver({
    onAdded(thread) {
      followThread(thread);
    },
    onRemoved(thread) {
      delete state.followed[thread.id];
    }
  });
}

function moduleKey(module) {
  return ptrHex(module.base) + ':' + module.size;
}

function excludeModuleIfNeeded(module) {
  if (!state.excludeNonTargetModules) {
    return;
  }
  if (moduleMatchesRequest(module, state.moduleName) ||
      moduleMatchesRequest(module, state.startModuleName) ||
      moduleMatchesRequest(module, state.stopModuleName)) {
    return;
  }

  const key = moduleKey(module);
  if (state.excludedModules[key]) {
    return;
  }

  Stalker.exclude({ base: module.base, size: module.size });
  state.excludedModules[key] = true;
}

function excludeNonTargetModules() {
  const modules = Process.enumerateModules();
  for (const module of modules) {
    excludeModuleIfNeeded(module);
  }
}

function startModuleObserver() {
  if (state.moduleObserver !== null) {
    return;
  }

  state.moduleObserver = Process.attachModuleObserver({
    onAdded(module) {
      try {
        resolveCandidateModule(module);
      } catch (e) {
        send({ type: 'agent-error', message: e.message });
      }
      excludeModuleIfNeeded(module);
    }
  });
}

function resolveCandidateModule(module) {
  if (state.module === null && moduleMatchesRequest(module, state.moduleName)) {
    state.module = module;
    state.moduleBase = module.base;
    state.moduleEnd = module.base.add(module.size);
  }
  if (state.startModule === null && moduleMatchesRequest(module, state.startModuleName)) {
    if (state.startRva >= module.size) {
      throw new Error('start RVA ' + hex(state.startRva) + ' is outside module ' + module.name + ' size ' + hex(module.size));
    }
    state.startModule = module;
    state.startModuleEnd = module.base.add(module.size);
    state.startAddress = module.base.add(state.startRva);
  }
  if (state.stopModule === null && moduleMatchesRequest(module, state.stopModuleName)) {
    if (state.endRva >= module.size) {
      throw new Error('stop RVA ' + hex(state.endRva) + ' is outside module ' + module.name + ' size ' + hex(module.size));
    }
    state.stopModule = module;
    state.stopModuleEnd = module.base.add(module.size);
    state.endAddress = state.endRva === 0 ? ptr(0) : module.base.add(state.endRva);
  }
  finishModuleResolution();
}

function finishModuleResolution() {
  if (state.ready || state.module === null || state.startModule === null || state.stopModule === null) {
    return;
  }

  state.ready = true;
  installExitListener();

  send({
    type: 'ready',
    module: state.module.name,
    path: state.module.path,
    base: ptrHex(state.module.base),
    size: state.module.size,
    startModule: state.startModule.name,
    stopModule: state.stopModule.name,
    startRva: hex(state.startRva),
    stopRva: hex(state.endRva),
    startAddress: ptrHex(state.startAddress),
    endAddress: ptrHex(state.endAddress)
  });

  if (state.gateAddress !== null) {
    installStalkerGate();
  } else {
    followExistingThreads();
    startThreadObserver();
  }
}

function waitForModule() {
  startModuleObserver();
  excludeNonTargetModules();

  for (const module of Process.enumerateModules()) {
    resolveCandidateModule(module);
  }
  if (!state.ready) {
    send({
      type: 'waiting-module',
      module: [state.moduleName, state.startModuleName, state.stopModuleName].join(',')
    });
  }
}

function currentThreadId() {
  return Process.getCurrentThreadId();
}

function snapshotRegisters(context) {
  const result = {};
  for (const name of ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rflags', 'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp', 'eflags']) {
    if (context[name] !== undefined) {
      result[name] = context[name].toString();
    }
  }
  return result;
}

function completePreviousInstruction(tid, currentRegisters) {
  const pending = state.pendingRegisters[tid];
  if (pending === undefined) {
    return;
  }

  const changes = {};
  for (const [name, before] of Object.entries(pending.before)) {
    const after = currentRegisters[name];
    if (after !== undefined && after !== before) {
      changes[name] = before + '->' + after;
    }
  }
  if (Object.keys(changes).length !== 0) {
    pending.row.registerChanges = changes;
  }
  delete state.pendingRegisters[tid];
}

function onInstruction(address, size, bytes, text, transfer, instructionState, sourceModule,
  blockStart, observeAfter, context) {
  if (state.done) {
    return;
  }

  const tid = currentThreadId();
  const isStart = isStartAddress(address);
  const isEnd = isStopAddress(address);

  if (!state.recording) {
    if (!isStart) {
      return;
    }

    state.recording = true;
    state.recordThreadId = tid;
    invalidatePreRecordingBlocks();
    send({
      type: 'recording-started',
      threadId: tid,
      address: ptrHex(address),
      blockStart: ptrHex(blockStart),
      rva: addressRva(address, sourceModule.base)
    });
  } else if (tid !== state.recordThreadId) {
    return;
  }

  const registers = snapshotRegisters(context);
  completePreviousInstruction(tid, registers);

  const row = {
    seq: state.count,
    tid,
    module: sourceModule.name,
    rva: addressRva(address, sourceModule.base),
    size,
    bytes,
    instruction: text
  };

  row.address = ptrHex(address);
  row.imageBase = ptrHex(sourceModule.base);
  row.registers = registers;
  row.readMask = instructionState.readMask;
  row.writeMask = instructionState.writeMask;
  row.memory = instructionState.memory.map(description => ({
    size: description.size,
    flags: description.flags,
    address: ptrHex(memoryEffectiveAddress(description, context))
  }));

  try {
    const target = transferTarget(transfer, context);
    const externalTarget = externalTargetNameFrom(target, sourceModule);
    if (externalTarget !== null) {
      row.externalTarget = externalTarget;
    }
  } catch (_) {
  }

  state.buffer.push(row);
  state.pendingRegisters[tid] = { row, before: registers };
  state.count += 1;

  if (state.buffer.length >= state.flushEvery) {
    flush();
  }

  if (state.endRva !== 0 && isEnd && !observeAfter && tid === state.recordThreadId) {
    finishTrace(tid, address, 'end-rva');
    return;
  }
}

function onEndInstructionComplete(address, context) {
  if (state.done) {
    return;
  }

  const tid = currentThreadId();
  if (tid !== state.recordThreadId) {
    return;
  }

  completePreviousInstruction(tid, snapshotRegisters(context));
  finishTrace(tid, address, 'end-rva');
}

function finishTrace(tid, address, reason) {
  if (state.done) {
    return;
  }

  state.done = true;
  state.pendingRegisters = {};
  flush(true);
  stopFollowing();
  send({
    type: 'done',
    reason,
    count: state.count,
    threadId: tid,
    address: ptrHex(address),
    rva: addressRva(address, moduleForAddress(address).base)
  });
}

rpc.exports = {
  start(config) {
    Stalker.trustThreshold = -1;

    state.moduleName = config.moduleName;
    state.startModuleName = config.startModuleName || state.moduleName;
    state.stopModuleName = config.stopModuleName || state.moduleName;
    state.startRva = config.startRva;
    state.endRva = config.endRva;
    state.targetOnly = config.targetOnly !== false;
    state.threadId = config.threadId === undefined ? null : config.threadId;
    state.gateAddress = config.gateAddress ? ptr(config.gateAddress) : null;
    state.recording = false;
    state.deferExclusions = state.targetOnly;
    state.excludeNonTargetModules = false;
    state.flushEvery = config.flushEvery || 256;

    if (!state.moduleName) {
      throw new Error('moduleName is required');
    }

    waitForModule();
  },

  stop() {
    state.done = true;
    state.pendingRegisters = {};
    flush(true);
    stopFollowing();

    if (state.observer !== null) {
      try {
        state.observer.detach();
      } catch (_) {
      }
      state.observer = null;
    }

    if (state.moduleObserver !== null) {
      try {
        state.moduleObserver.detach();
      } catch (_) {
      }
      state.moduleObserver = null;
    }

    if (state.gateListener !== null) {
      try {
        state.gateListener.detach();
      } catch (_) {
      }
      state.gateListener = null;
    }
    if (state.exitListener !== null) {
      try {
        state.exitListener.detach();
      } catch (_) {
      }
      state.exitListener = null;
    }
  }
};
