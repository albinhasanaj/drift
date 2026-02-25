// prettier-ignore
/* eslint-disable */
// @ts-nocheck
/* Platform-specific loader for drift-cortex-napi native binary */

const { existsSync } = require('node:fs')
const { join } = require('node:path')

let nativeBinding = null
const loadErrors = []

// Platform + arch → binary filename mapping
const platforms = {
  'darwin-arm64': 'drift-cortex-napi.darwin-arm64.node',
  'darwin-x64': 'drift-cortex-napi.darwin-x64.node',
  'linux-x64-gnu': 'drift-cortex-napi.linux-x64-gnu.node',
  'linux-arm64-gnu': 'drift-cortex-napi.linux-arm64-gnu.node',
  'win32-x64-msvc': 'drift-cortex-napi.win32-x64-msvc.node',
}

function requireNative() {
  const platform = process.platform
  const arch = process.arch
  let key

  if (platform === 'darwin') {
    key = `darwin-${arch}`
  } else if (platform === 'linux') {
    key = `linux-${arch}-gnu`
  } else if (platform === 'win32') {
    key = `win32-${arch}-msvc`
  }

  if (!key || !platforms[key]) {
    throw new Error(`Unsupported platform: ${platform}-${arch}`)
  }

  const localPath = join(__dirname, platforms[key])
  if (existsSync(localPath)) {
    try {
      return require(localPath)
    } catch (e) {
      loadErrors.push(e)
    }
  }

  // Try platform-specific npm package
  const pkgName = `drift-cortex-napi-${key}`
  try {
    return require(pkgName)
  } catch (e) {
    loadErrors.push(e)
  }

  return null
}

nativeBinding = requireNative()

if (!nativeBinding) {
  if (loadErrors.length > 0) {
    throw new Error(
      `Failed to load native binding for drift-cortex-napi.\n` +
      loadErrors.map(e => e.message).join('\n')
    )
  }
  throw new Error(`No native binding found for platform: ${process.platform}-${process.arch}`)
}

module.exports = nativeBinding
