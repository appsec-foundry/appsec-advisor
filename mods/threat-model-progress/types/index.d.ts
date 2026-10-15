export type Progress = { file: string | undefined; lines: string[] }

declare module 'claude-code' {
  interface PluginState {
    'threat-model-progress': { progress: Progress }
  }
}
