export {};

// Suppress ExperimentalWarning noise from dependencies that import JSON modules.
// Must run before cli-core.js's static import chain loads — set synchronously here,
// then load the implementation via dynamic import so the Proxy is active first.
// @ts-ignore
process.emit = new Proxy(process.emit, {
  apply(target, thisArg, args) {
    if (args[0] === 'warning' && (args[1] as { name?: string })?.name === 'ExperimentalWarning') {
      return false;
    }
    return Reflect.apply(target, thisArg, args);
  },
});

await import('./cli-core.js');
