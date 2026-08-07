import { join } from 'path'

import { fileExists, getRepo, loudExec, quietExec } from './common'
import { getObjcopyPath } from './ios-tools'

export const tmpPath = join(__dirname, '../../tmp')

// Matches the Edge app NDK version
// The Zano build used '27.2.12479018', so we could try upgrading.
export const NDK_VERSION = '26.1.10909125'

/**
 * Tool locations.
 * The naming here matches the standard Makefile convention.
 */
export interface ToolPaths {
  AR: string
  // AS: string
  CC: string
  // CCLD: string
  // CPP: string
  CXX: string
  LD: string
  // NM: string
  OBJCOPY: string
  // OBJDUMP: string
  RANLIB: string
  // STRINGS: string
  // STRIP: string
}

export interface ToolFlags {
  CFLAGS: string
  CPPFLAGS: string
  CXXFLAGS: string
  LDFLAGS: string
}

/**
 * Fields shared between iOS and Android.
 */
export interface CommonPlatform {
  /** CPU, such as x86 or arm64 */
  arch: string

  /** Name for use in paths, logs, etc. */
  name: string

  /** Where to find libraries and headers. */
  sysroot: string

  /** Paths to individual tools like compilers & linkers */
  tools: ToolPaths

  /** The GNU-style patform name used in a lot of build tools */
  triple: string

  /** The magic flags CMake needs */
  cmakeFlags: string[]
}

export interface AndroidPlatform extends CommonPlatform {
  type: 'android'
  ndkPath: string
  api: number
}

export interface IosPlatform extends CommonPlatform {
  type: 'ios'
  sdk: 'iphoneos' | 'iphonesimulator'
  version: string
  sdkFlags: ToolFlags
}

export type Platform = AndroidPlatform | IosPlatform

export const makePlatforms = async (): Promise<Platform[]> => [
  ...(await makeAndroidPlatforms()),
  ...(await makeIosPlatforms())
]

/**
 * Gathers information about the NDK and its various tools,
 * per platform we support.
 */
export async function makeAndroidPlatforms(
  ndkVersion: string = NDK_VERSION
): Promise<AndroidPlatform[]> {
  const api = 23
  const inputs = [
    { arch: 'arm64-v8a', triple: 'aarch64-linux-android' },
    { arch: 'armeabi-v7a', triple: 'armv7a-linux-androideabi' },
    { arch: 'x86', triple: 'i686-linux-android' },
    { arch: 'x86_64', triple: 'x86_64-linux-android' }
  ] as const

  const { ANDROID_HOME } = process.env
  if (ANDROID_HOME == null) {
    throw new Error('ANDROID_HOME is not set in the environment.')
  }

  // Install the NDK if we need it:
  const ndkPath = join(ANDROID_HOME, 'ndk', ndkVersion)
  const hasNdk = await fileExists(ndkPath)
  if (!hasNdk) {
    console.log(`Installing NDK ${ndkVersion}...`)
    const sdkManagerPath = join(
      ANDROID_HOME,
      'cmdline-tools/latest/bin/sdkmanager'
    )
    await loudExec(sdkManagerPath, [`"ndk;${ndkVersion}"`])
  }

  // Find the prebuilt toolchain:
  const darwinSysroot = `${ndkPath}/toolchains/llvm/prebuilt/darwin-x86_64`
  const linuxSysroot = `${ndkPath}/toolchains/llvm/prebuilt/linux-x86_64`
  const sysroot = (await fileExists(darwinSysroot))
    ? darwinSysroot
    : linuxSysroot

  const out: AndroidPlatform[] = []
  for (const { arch, triple } of inputs) {
    out.push({
      type: 'android',
      ndkPath,
      api,

      arch,
      name: `android-${arch}`,
      cmakeFlags: [
        // `-DCMAKE_TOOLCHAIN_FILE=${ndkPath}/build/cmake/android.toolchain.cmake`,
        // `-DANDROID_ABI=${api}`,
        // `-DANDROID_PLATFORM=android-${api}`,
        `-DCMAKE_ANDROID_ARCH_ABI=${arch}`,
        `-DCMAKE_ANDROID_NDK=${ndkPath}`,
        `-DCMAKE_ANDROID_STL_TYPE=c++_shared`,
        // Force NDK archivers. Without these, CMake picks the host
        // /usr/bin/ar, which silently drops ELF members on modern macOS
        // ("not a mach-o file") and leaves empty 96-byte .a stubs that
        // then fail the ffi link with undefined monero/lwsf symbols.
        `-DCMAKE_AR=${sysroot}/bin/llvm-ar`,
        `-DCMAKE_RANLIB=${sysroot}/bin/llvm-ranlib`,
        `-DCMAKE_CXX_COMPILER_AR=${sysroot}/bin/llvm-ar`,
        `-DCMAKE_CXX_COMPILER_RANLIB=${sysroot}/bin/llvm-ranlib`,
        `-DCMAKE_C_COMPILER_AR=${sysroot}/bin/llvm-ar`,
        `-DCMAKE_C_COMPILER_RANLIB=${sysroot}/bin/llvm-ranlib`,
        `-DCMAKE_SYSTEM_NAME=Android`,
        `-DCMAKE_SYSTEM_VERSION=${api}`
      ],
      sysroot,
      tools: {
        AR: `${sysroot}/bin/llvm-ar`,
        CC: `${sysroot}/bin/${triple}${api}-clang`,
        CXX: `${sysroot}/bin/${triple}${api}-clang++`,
        LD: `${sysroot}/bin/${triple}${api}-clang++`,
        OBJCOPY: `${sysroot}/bin/llvm-objcopy`,
        RANLIB: `${sysroot}/bin/llvm-ranlib`
      },
      triple
    })
  }
  return out
}

/**
 * Gathers information about the iOS SDK and its various tools,
 * per platform we support.
 */
export async function makeIosPlatforms(): Promise<IosPlatform[]> {
  const version = '13.0'
  const inputs = [
    { sdk: 'iphoneos', arch: 'arm64', cmakePlatform: 'OS64' },
    { sdk: 'iphonesimulator', arch: 'arm64', cmakePlatform: 'SIMULATORARM64' },
    { sdk: 'iphonesimulator', arch: 'x86_64', cmakePlatform: 'SIMULATOR64' }
  ] as const

  const objcopyPath = await getObjcopyPath()
  await getRepo(
    'ios-cmake',
    'https://github.com/leetal/ios-cmake.git',
    '99f99df73dc752c7e88916fc1f9df6b9f8c40f8d' // 4.5.0
  )

  const out: IosPlatform[] = []
  for (const { arch, sdk, cmakePlatform } of inputs) {
    const sysroot = await quietExec('xcrun', ['--sdk', sdk, '--show-sdk-path'])

    // These two ecosystems disagree about target triples:
    const clangTriple =
      sdk === 'iphoneos'
        ? `${arch}-apple-ios${version}`
        : `${arch}-apple-ios${version}-simulator`
    const gnuTriple = `${arch}-apple-darwin13`

    const CFLAGS = `-arch ${arch} -miphoneos-version-min=13.0 -isysroot ${sysroot} -target ${clangTriple}`

    out.push({
      type: 'ios',
      sdk,
      sdkFlags: {
        CFLAGS,
        CPPFLAGS: `-isysroot ${sysroot}`,
        CXXFLAGS: CFLAGS,
        LDFLAGS: `-isysroot ${sysroot}`
      },
      version,

      arch,
      name: `${sdk}-${arch}`,
      cmakeFlags: [
        `-DCMAKE_SYSTEM_NAME=iOS`,
        `-DCMAKE_TOOLCHAIN_FILE=${join(tmpPath, 'ios-cmake/ios.toolchain.cmake')}`,
        `-DCMAKE_XCODE_ATTRIBUTE_ONLY_ACTIVE_ARCH=NO`,
        `-DPLATFORM=${cmakePlatform}`
      ],
      sysroot,
      tools: {
        AR: await quietExec('xcrun', ['--sdk', sdk, '--find', 'ar']),
        CC: await quietExec('xcrun', ['--sdk', sdk, '--find', 'clang']),
        CXX: await quietExec('xcrun', ['--sdk', sdk, '--find', 'clang++']),
        LD: await quietExec('xcrun', ['--sdk', sdk, '--find', 'ld']),
        RANLIB: await quietExec('xcrun', ['--sdk', sdk, '--find', 'ranlib']),
        OBJCOPY: objcopyPath
      },
      triple: gnuTriple
    })
  }
  return out
}
