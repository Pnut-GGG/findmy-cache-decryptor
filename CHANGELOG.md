# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of FindMy Cache Decryptor
- Support for ChaCha20-Poly1305 AEAD decryption
- Automatic detection of FMIP and FMF cache files
- Nested plist key format support
- Comprehensive error handling and logging
- Bilingual README (English/Chinese)

### Features
- Decrypt `SafeLocations.data` - Safe location definitions
- Decrypt `Items.data` - Tracked items information  
- Decrypt `Devices.data` - Device location data
- Decrypt `FamilyMembers.data` - Family member information
- Decrypt `ItemGroups.data` - Item grouping data
- Decrypt `Owner.data` - Account owner information
- Decrypt `FriendCacheData.data` - Friends location data

### Technical Details
- Reverse engineered from macOS 14.4+ FindMy frameworks
- Supports both direct and nested plist key formats
- Automatic nonce extraction from encrypted data
- Proper authentication tag verification
- Human-readable output formatting

### Documentation
- Comprehensive installation guide
- Step-by-step usage instructions
- Technical implementation details
- Reverse engineering methodology
- Security considerations

## [1.0.0] - 2024-07-16

### Added
- Initial project structure
- Core decryption functionality
- Support for macOS 14.4+ encrypted cache files
- Automatic key loading from plist files
- Manual key input fallback
- Comprehensive error handling

### Security
- Proper cryptographic implementation
- Key validation and verification
- Secure memory handling for sensitive data

### Documentation
- README with installation and usage instructions
- Technical documentation of encryption scheme
- Acknowledgments to contributing projects

---

## Development Notes

### Reverse Engineering Process
1. **Framework Analysis**: Analyzed Find My.app → FMIPCore.framework → FindMyCrypto.framework
2. **Algorithm Discovery**: Identified ChaCha20-Poly1305 AEAD encryption
3. **Key Structure**: Reverse engineered plist key format with privateKey and symmetricKey
4. **Data Format**: Analyzed encryptedData structure with nonce, ciphertext, and auth tag
5. **Implementation**: Created Python implementation with proper error handling

### Testing
- Tested on macOS 14.4+
- Verified decryption of all supported cache file types
- Validated against known good data
- Cross-referenced with original Apple frameworks

### Future Enhancements
- [ ] Support for additional cache file formats
- [ ] GUI interface for easier use
- [ ] Batch processing capabilities
- [ ] Enhanced error reporting
- [ ] Performance optimizations 