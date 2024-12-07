# Internal DLL Loader with Memory Protection

A sophisticated DLL loader that pre-allocates memory space and maintains execution rights throughout the DLL lifecycle.

## Features

- Pre-allocates memory space at random address
- Continuously monitors and restores memory protection rights
- Supports dynamic DLL loading/unloading
- Memory protection against external modifications
- Detailed logging of all operations

## How It Works

1. **Initialization**:
   - Allocates memory space with PAGE_EXECUTE_READWRITE permissions
   - Calculates required space by reading the target DLL's PE headers
   - Chooses random memory location for allocation
   - Starts memory protection monitoring thread

2. **Memory Protection**:
   - Continuously monitors allocated memory region
   - Automatically restores PAGE_EXECUTE_READWRITE permissions if changed
   - Provides logging of any protection changes

3. **DLL Management**:
   - Loads DLL on demand (F6 key)
   - Properly initializes DLL entry point
   - Supports clean unloading (F7 key)
   - Graceful shutdown (F9 key)

## Usage

1. **Setup**:
   - Place your target DLL (named `example.dll`) in the same directory as the loader
   - Inject the loader DLL into your target process

2. **Controls**:
   - `F6`: Load example.dll
   - `F7`: Unload example.dll
   - `F9`: Exit loader

3. **Monitoring**:
   - Console window shows real-time status and operations
   - Displays memory addresses and protection states
   - Reports any attempts to modify memory protection

## Technical Details

- Uses Windows API for memory management
- Implements PE header parsing
- Maintains memory protection through VirtualProtect
- Supports x64 architecture
- Thread-safe operations

## Requirements

- Windows operating system
- Administrative privileges (for some operations)
- Target process must allow DLL injection
- Example.dll must be present in the same directory

## Security Features

- Random memory allocation
- Continuous memory protection monitoring
- Protection rights restoration
- Privilege verification
- Detailed error reporting

## Error Handling

The loader provides comprehensive error reporting for:
- Memory allocation failures
- DLL loading issues
- Protection changes
- Access violations
- General operation errors

## Notes

- Ensure your target DLL is compatible with the process architecture
- Monitor console output for operation status
- Memory protection monitoring runs until loader is unloaded
- Clean shutdown is recommended using F9 key 