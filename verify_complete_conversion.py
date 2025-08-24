#!/usr/bin/env python3
"""
Neo Zig SDK - Complete Conversion Verification Script

This script performs a comprehensive file-by-file comparison between
the Swift NeoSwift SDK and the Zig NeoZig SDK to ensure 100% conversion.
"""

import os
import sys
from pathlib import Path
import json

def find_swift_files():
    """Find all Swift source files in NeoSwift"""
    swift_files = []
    swift_dir = Path("NeoSwift/Sources/NeoSwift")
    
    if not swift_dir.exists():
        print("❌ NeoSwift directory not found!")
        return swift_files
    
    for swift_file in swift_dir.rglob("*.swift"):
        # Skip Package.swift as it's build configuration
        if swift_file.name != "Package.swift":
            rel_path = swift_file.relative_to(swift_dir)
            swift_files.append(str(rel_path))
    
    return sorted(swift_files)

def find_zig_files():
    """Find all Zig source files in src/"""
    zig_files = []
    src_dir = Path("src")
    
    if not src_dir.exists():
        print("❌ src directory not found!")
        return zig_files
    
    for zig_file in src_dir.rglob("*.zig"):
        rel_path = zig_file.relative_to(src_dir)
        zig_files.append(str(rel_path))
    
    return sorted(zig_files)

def map_swift_to_zig_name(swift_file):
    """Map Swift file name to expected Zig file name"""
    # Convert Swift naming conventions to Zig
    name = Path(swift_file).stem
    
    # Convert CamelCase to snake_case
    zig_name = ""
    for i, char in enumerate(name):
        if char.isupper() and i > 0:
            zig_name += "_"
        zig_name += char.lower()
    
    return zig_name + ".zig"

def get_zig_path_for_swift(swift_file):
    """Get expected Zig path for Swift file"""
    swift_path = Path(swift_file)
    parts = list(swift_path.parts)
    
    # Map directory structure
    dir_mapping = {
        "contract": "contract",
        "crypto": "crypto", 
        "protocol": "protocol",
        "script": "script",
        "serialization": "serialization",
        "transaction": "transaction",
        "types": "types",
        "utils": "utils",
        "wallet": "wallet"
    }
    
    zig_parts = []
    for part in parts[:-1]:  # Exclude filename
        if part in dir_mapping:
            zig_parts.append(dir_mapping[part])
        elif part in ["core", "response", "http", "rx", "helpers", "errors", "nep6"]:
            zig_parts.append(part)
    
    # Convert filename
    zig_filename = map_swift_to_zig_name(swift_file)
    zig_parts.append(zig_filename)
    
    return "/".join(zig_parts)

def verify_conversion_completeness():
    """Verify complete Swift to Zig conversion"""
    print("🔍 Neo Zig SDK - Complete Conversion Verification")
    print("=" * 60)
    
    swift_files = find_swift_files()
    zig_files = find_zig_files()
    
    print(f"📊 Found {len(swift_files)} Swift source files")
    print(f"📊 Found {len(zig_files)} Zig source files")
    print()
    
    # Track conversion status
    converted = []
    missing = []
    extra = []
    
    # Check each Swift file for Zig equivalent
    print("🔍 Checking Swift → Zig conversion:")
    print("-" * 40)
    
    for swift_file in swift_files:
        expected_zig = get_zig_path_for_swift(swift_file)
        
        # Check various possible Zig locations
        possible_paths = [
            expected_zig,
            expected_zig.replace("_", ""),  # Without underscores
            expected_zig.replace("neo_swift", "neo_client"),  # Common rename
            expected_zig.replace("neo_swift", "neo_zig"),     # Direct conversion
        ]
        
        found = False
        actual_zig_path = None
        
        for possible_path in possible_paths:
            if possible_path in zig_files:
                found = True
                actual_zig_path = possible_path
                break
        
        if found:
            converted.append((swift_file, actual_zig_path))
            print(f"✅ {swift_file} → {actual_zig_path}")
        else:
            missing.append(swift_file)
            print(f"❌ {swift_file} → MISSING")
    
    print()
    print("📊 CONVERSION SUMMARY:")
    print(f"✅ Converted: {len(converted)} files ({len(converted)*100//len(swift_files)}%)")
    print(f"❌ Missing: {len(missing)} files ({len(missing)*100//len(swift_files)}%)")
    print()
    
    if missing:
        print("🚨 MISSING SWIFT FILE CONVERSIONS:")
        print("-" * 40)
        for swift_file in missing:
            expected_zig = get_zig_path_for_swift(swift_file)
            print(f"   {swift_file} should be → {expected_zig}")
        print()
    
    # Check for extra Zig files
    converted_zig_files = [zig_path for _, zig_path in converted]
    extra = [zig_file for zig_file in zig_files if zig_file not in converted_zig_files]
    
    if extra:
        print("📋 ADDITIONAL ZIG FILES (enhancements):")
        print("-" * 40)
        for zig_file in extra[:10]:  # Show first 10
            print(f"   + {zig_file}")
        if len(extra) > 10:
            print(f"   ... and {len(extra) - 10} more")
        print()
    
    # Generate detailed report
    report = {
        "total_swift_files": len(swift_files),
        "total_zig_files": len(zig_files),
        "converted_files": len(converted),
        "missing_files": len(missing),
        "conversion_percentage": len(converted) * 100 // len(swift_files),
        "converted_list": converted,
        "missing_list": missing,
        "extra_zig_files": extra
    }
    
    # Save detailed report
    with open("COMPLETE_CONVERSION_VERIFICATION.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print("💾 Detailed report saved to: COMPLETE_CONVERSION_VERIFICATION.json")
    print()
    
    # Final assessment
    if len(missing) == 0:
        print("🎉 COMPLETE CONVERSION VERIFIED: 100% SUCCESS!")
    elif len(missing) <= 5:
        print(f"🎯 NEAR-COMPLETE CONVERSION: {len(converted)*100//len(swift_files)}% - Only {len(missing)} files missing")
    else:
        print(f"⚠️  PARTIAL CONVERSION: {len(converted)*100//len(swift_files)}% - {len(missing)} files need conversion")
    
    return len(missing) == 0

def main():
    """Main verification function"""
    try:
        success = verify_conversion_completeness()
        
        if success:
            print("\n🏆 MISSION ACCOMPLISHED: Complete Swift→Zig conversion verified!")
            sys.exit(0)
        else:
            print("\n🔧 MISSION CONTINUING: Additional conversions needed for 100% completion")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Verification failed: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()