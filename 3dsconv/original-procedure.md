## globals
1. mu, 0x200
2. read_size, 0x800000
3. zerokey, [0u8;0x10]
4. original\_ncch\_key,
5. certchain\_retail,
6. ticket\_tmd,

## procedures
### pre-process
1. open source file, as rom
2. check for NCSD magic, 0x100, 4 bytes
3. check for title_id, 0x108, 8 bytes, reverse
4. get partitions size, 0x120
5. game\_cxi\_offset, 4 bytes, u32, *mu
6. game\_cxi\_size, 4 bytes, u32, *mu
7. manual\_cfa\_offset, 4 bytes, u32, *mu
8. manual\_cfa\_size, 4 bytes, u32, *mu
9. dlpchild\_cfa\_offset, 4 bytes, u32, *mu
10. dlpchild\_cfa\_size, 4 bytes, u32, *mu
11. check for NCCH magic, game\_cxi\_offset + 0x100, 4 bytes
12. check for encryption type as encryption\_bitmask, game\_cxi\_offset + 0x18F, 1 byte
13. encrypted = ~encryption\_bitmask & 0x4,
14. zerokey\_encrypted = encryption\_bitmask & 0x1
15. decryption_key
    1. zerokey\_encrypted == true, decryption_key = zerokey
    2. zerokey\_encrypted == false,
        1. key\_y, at game\_cxi\_offset, 0x10 bytes,
        2. decryption\_key = rol(rol(original\_ncch\_key,2,128)^key_y+0x1FF9E9AAC5FE0408024591DC5D52768A,87,128)
16. extheader, game\_cxi\_offset + 0x200, 0x400 byptes, **decrypt it if encrypted**
17. extheader_hash = sha256(extheader)
18. ncch\_extheader\_hash, 0x4160, 0x20 byptes, should match above extheader_hash
19. patch extheader, extheader[0xD] |= 2
20. new\_extheader\_hash = sha256(extheader)
21. dependency\_list = extheader[0x40:0x1C0]
22. save\_size = extheader[0x1C0:0x1C4]
23. **re-encrypt extheader if encrypted**
24. ncch\_header, game\_cxi\_offset, 0x200 bytes
25. ncch\_header[0x160:0x180] = new\_extheader\_hash
26. exefs\_offset = ncch_header[0x1A0:0x1A4] * mu
27. exefs\_file\_header, game\_cxi\_offset + exefs\_offset, 0x40 bytes, **decrypt it if encrypted**
28. exefs\_icon\_offset, between exefs\_file\_header[0x0] and exefs\_file\_header[0x3f], every 0x10 bytes, for this starts with 0x8 bytes for string "icon", following with 0x4 bytes as exefs\_icon\_offset
29. exefs\_icon, current + exefs\_icon\_offset + 0x200 - 0x40, 0x36C0 bytes, **decrypt it if encrypted**
30. tmd_padding, [u8;0xC]
31. content_count, 1u8
32. tmd_size, 0xB34 u32
33. content_index, 0b10000000 u8
34. if manual\_cfa\_offset
    1. tmd_padding += [u8;0x10]
    2. content_count += 1
    3. tmd_size += 0x30
    4. content_index += 0b01000000
35. dlpchild\_cfa\_offset
    1. tmd_padding += [u8;0x10]
    2. content_count += 1
    3. tmd_size += 0x30
    4. content_index += 0b00100000
### cia write (big-endian)
1. chunk\_records = [0u32;3] + [game\_cxi\_size u32] + [0u8;0x20]\(sha256\)
2. if manual\_cfa\_offset
    1. chunk\_records += [2u32,0x20000u32,0u32] + [manual\_cfa\_size u32] + [0u8;0x20]\(sha256\)
3. if dlpchild\_cfa\_offset
    1. chunk\_records += [2u32,0x20000u32,0u32] + [dlpchild\_cfa\_size u32] + [0u8;0x20]\(sha256\)
4. content\_size = game\_cxi\_size + manual\_cfa\_size + dlpchild\_cfa\_size
5. cia.write(
    [0x2020u32, 0u32, 0xA00u32, 0x350u32] +
    [tmd\_size u32, 0x3AC0u32, content\_size u32] +
    [0u8, content_index u8] + [0u8;0x201F] +
    certchain\_retail + ticket\_tmd + chunk\_records + tmd\_padding
    )
6. cia.write([content_count u8]) at 0x2F9F
7. cia.write(title_id) at 0x2C1C
8. cia.write(title_id) at 0x2F4C
9. cia.write(save_size) at 0x2F5A
10. game\_cxi\_hash = sha256(ncch\_header + extheader); *CXI NCCH Header + first-half ExHeader*
11. cia.write(ncch\_header + extheader) at end
12. rom.seek(game\_cxi\_offset + 0x200 + 0x400); *CXI second-half ExHeader + contents*
13. left = game\_cxi\_size - 0x200 - 0x400
14. game\_cxi = row.read(left) from current
15. game\_cxi\_hash.update(game_cxi)
16. cia.write(game\_cxi) at end
17. cia.write(game\_cxi\_hash) at 0x38D4
18. chunk\_records[0x10:0x30] = game\_cxi\_hash
19. cr_offset = 0
20. if manual\_cfa\_offset
    1. manual\_cfa = rom.read(manual\_cfa\_size) from manual\_cfa\_offset
    2. cia.write(manual\_cfa) at end
    3. manual\_cfa\_hash = sha256(manual\_cfa)
    4. cia.write(manual\_cfa\_hash) at 0x3904
    5. chunk\_records[0x40:0x60] = manual\_cfa\_hash
    6. cr\_offset += 0x30
21. if dlpchild\_cfa\_offset
    1. dlpchild\_cfa = rom.read(dlpchild\_cfa\_size) from dlpchild\_cfa\_offset
    2. dlpchild\_cfa\_hash = sha256(dlpchild\_cfa)
    3. cia.write( dlpchild\_cfa) at end
    3. cia.write(dlpchild\_cfa\_hash) at 0x3904 + cr_offset
    4. chunk\_records[0x40 + cr\_offset:0x60 + cr\_offset]= dlpchild\_cfa\_hash
22. chunk\_records\_hash = sha256(chunk\_records)
23. cia.write([content\_count u8] + chunk\_records\_hash) at 0x2FC7
24. info\_records\_hash = sha256([u8;3] + [content\_count u8] + chunk\_records\_hash + [u8;0x8DC])
25. cia.write(info\_records\_hash) at 0x2FA4
26. cia.write(dependency\_list + [u8;0x180] + [2u8] + [u8;0xFC] + exefs\_icon) at end