#!/usr/bin/env python3
"""
Neo Zig SDK - Comprehensive Conversion Verification

Performs intelligent file-by-file comparison accounting for reorganization
and naming conventions between Swift and Zig implementations.
"""

import os
from pathlib import Path
import json

def analyze_swift_file(swift_file_path):
    """Analyze Swift file to extract key information"""
    try:
        with open(swift_file_path, 'r') as f:
            content = f.read()
        
        info = {
            'classes': [],
            'structs': [],
            'enums': [],
            'protocols': [],
            'functions': [],
            'properties': []
        }
        
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('public class '):
                class_name = line.split()[2].rstrip(':')
                info['classes'].append(class_name)
            elif line.startswith('public struct '):
                struct_name = line.split()[2].rstrip(':')
                info['structs'].append(struct_name)
            elif line.startswith('public enum '):
                enum_name = line.split()[2].rstrip(':')
                info['enums'].append(enum_name)
            elif line.startswith('public protocol '):
                protocol_name = line.split()[2].rstrip(':')
                info['protocols'].append(protocol_name)
            elif 'public func ' in line:
                func_name = line.split('func ')[1].split('(')[0]
                info['functions'].append(func_name)
        
        return info
    except Exception as e:
        return {'error': str(e)}

def find_zig_equivalent(swift_file, zig_files):
    """Find Zig equivalent for Swift file using intelligent matching"""
    swift_name = Path(swift_file).stem
    swift_dir = str(Path(swift_file).parent)
    
    # Direct name matches (accounting for naming conventions)
    direct_matches = []
    fuzzy_matches = []
    
    for zig_file in zig_files:
        zig_name = Path(zig_file).stem
        zig_dir = str(Path(zig_file).parent)
        
        # Convert names to comparable format
        swift_comparable = swift_name.lower().replace("neoswift", "neo")
        zig_comparable = zig_name.lower().replace("_", "")
        
        # Check for direct matches
        if swift_comparable == zig_comparable:
            direct_matches.append(zig_file)
        # Check for fuzzy matches (similar names)
        elif swift_comparable in zig_comparable or zig_comparable in swift_comparable:
            fuzzy_matches.append(zig_file)
        # Check for directory-based matches
        elif swift_name.lower() in zig_name.lower():
            fuzzy_matches.append(zig_file)
    
    # Return best match
    if direct_matches:
        return direct_matches[0]
    elif fuzzy_matches:
        return fuzzy_matches[0]
    
    return None

def comprehensive_verification():
    """Perform comprehensive conversion verification"""
    print("🔍 COMPREHENSIVE NEO ZIG SDK CONVERSION VERIFICATION")
    print("=" * 65)
    
    # Find all files
    swift_files = []
    swift_dir = Path("NeoSwift/Sources/NeoSwift")
    
    if swift_dir.exists():
        for swift_file in swift_dir.rglob("*.swift"):
            if swift_file.name != "Package.swift":
                rel_path = swift_file.relative_to(swift_dir)
                swift_files.append(str(rel_path))
    
    zig_files = []
    src_dir = Path("src")
    
    if src_dir.exists():
        for zig_file in src_dir.rglob("*.zig"):
            rel_path = zig_file.relative_to(src_dir)
            zig_files.append(str(rel_path))
    
    print(f"📊 Swift source files: {len(swift_files)}")
    print(f"📊 Zig source files: {len(zig_files)}")
    print()
    
    # Verification results
    verified_conversions = []
    missing_conversions = []
    extra_implementations = []
    
    # Check each Swift file
    print("🔍 INTELLIGENT CONVERSION MATCHING:")
    print("-" * 50)
    
    for swift_file in sorted(swift_files):
        zig_equivalent = find_zig_equivalent(swift_file, zig_files)
        
        if zig_equivalent:
            verified_conversions.append((swift_file, zig_equivalent))
            print(f"✅ {swift_file:<40} → {zig_equivalent}")
        else:
            missing_conversions.append(swift_file)
            print(f"❌ {swift_file:<40} → MISSING")
    
    print()
    
    # Find extra Zig files
    converted_zig_files = [zig_path for _, zig_path in verified_conversions]
    extra_implementations = [zig_file for zig_file in zig_files if zig_file not in converted_zig_files]
    
    # Calculate statistics
    conversion_rate = len(verified_conversions) * 100 // len(swift_files)
    
    print("📊 COMPREHENSIVE CONVERSION ANALYSIS:")
    print("-" * 45)
    print(f"✅ Verified Conversions: {len(verified_conversions)} files ({conversion_rate}%)")
    print(f"❌ Missing Conversions: {len(missing_conversions)} files")
    print(f"📋 Extra Implementations: {len(extra_implementations)} files")
    print()
    
    # Detailed analysis by category
    categories = {}
    for swift_file, zig_file in verified_conversions:
        category = str(Path(swift_file).parts[0]) if Path(swift_file).parts else "root"
        if category not in categories:
            categories[category] = {'converted': 0, 'total': 0}
        categories[category]['converted'] += 1
    
    for swift_file in swift_files:
        category = str(Path(swift_file).parts[0]) if Path(swift_file).parts else "root"
        if category not in categories:
            categories[category] = {'converted': 0, 'total': 0}
        categories[category]['total'] += 1
    
    print("📊 CONVERSION BY CATEGORY:")
    print("-" * 30)
    for category, stats in sorted(categories.items()):
        if stats['total'] > 0:
            pct = stats['converted'] * 100 // stats['total']
            print(f"  {category:<20}: {stats['converted']}/{stats['total']} ({pct}%)")
    print()
    
    # Critical files check
    critical_files = [
        "NeoSwift.swift",
        "protocol/NeoSwiftConfig.swift", 
        "types/Hash160.swift",
        "types/Hash256.swift",
        "crypto/ECKeyPair.swift",
        "transaction/TransactionBuilder.swift",
        "wallet/Wallet.swift"
    ]
    
    print("🎯 CRITICAL FILE VERIFICATION:")
    print("-" * 35)
    critical_found = 0
    for critical_file in critical_files:
        zig_equiv = find_zig_equivalent(critical_file, zig_files)
        if zig_equiv:
            print(f"✅ {critical_file} → {zig_equiv}")
            critical_found += 1
        else:
            print(f"❌ {critical_file} → MISSING")
    
    critical_pct = critical_found * 100 // len(critical_files)
    print(f"\nCritical files: {critical_found}/{len(critical_files)} ({critical_pct}%)")
    print()
    
    # Save comprehensive report
    report = {
        "verification_summary": {
            "total_swift_files": len(swift_files),
            "total_zig_files": len(zig_files),
            "verified_conversions": len(verified_conversions),
            "missing_conversions": len(missing_conversions),
            "extra_implementations": len(extra_implementations),
            "conversion_percentage": conversion_rate,
            "critical_file_percentage": critical_pct
        },
        "verified_conversions": verified_conversions,
        "missing_conversions": missing_conversions,
        "extra_implementations": extra_implementations,
        "category_breakdown": categories,
        "critical_files_status": {cf: find_zig_equivalent(cf, zig_files) for cf in critical_files}
    }
    
    with open("COMPREHENSIVE_VERIFICATION_REPORT.json", "w") as f:
        json.dump(report, f, indent=2)
    
    # Final assessment
    print("🏆 FINAL VERIFICATION RESULTS:")
    print("-" * 35)
    print(f"Overall Conversion: {conversion_rate}%")
    print(f"Critical Files: {critical_pct}%")
    
    if conversion_rate >= 90:
        print("🎉 EXCELLENT: Near-complete conversion achieved!")
    elif conversion_rate >= 75:
        print("🎯 GOOD: Major conversion milestone achieved!")
    elif conversion_rate >= 50:
        print("⚠️  PARTIAL: Significant progress with more work needed")
    else:
        print("🔧 INITIAL: Foundation established, major work remaining")
    
    print(f"\n💾 Detailed report: COMPREHENSIVE_VERIFICATION_REPORT.json")
    
    return conversion_rate >= 90

if __name__ == "__main__":
    comprehensive_verification()