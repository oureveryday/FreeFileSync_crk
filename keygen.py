import hashlib
import struct
import os
import win32file
import win32con
import win32api
import ctypes
import zlib
# 常量定义
SALT = b"zadf%231d34kjjf"
VERSION = b"14.6"
INITIAL_KEY = 90  # 0x5A
KEY_MODIFIER = 53

def generate_registered_dat(filename="Registered.dat", name="User", email="user@example.com", key_type="donation", version=VERSION):
    """
    生成可以通过 FreeFileSync 校验的 Registered.dat 文件。
    """
    # 1. 准备 Payload (484 字节)
    # 格式: [Name] \0 [Email] \0 [Type] \0 ... padding ...
    payload_size = 484
    
    b_name = name.encode('utf-8') + b'\x00'
    b_email = email.encode('utf-8') + b'\x00'
    b_type = key_type.encode('utf-8') + b'\x00' # "donation" or "business"
    
    payload_data = b_name + b_email + b_type
    
    if len(payload_data) > payload_size:
        raise ValueError(f"User data too long! Max {payload_size} bytes.")
    
    # 填充剩余部分为 0
    payload_padded = payload_data.ljust(payload_size, b'\x00')
    
    # 2. 构建 Hash 输入数据
    # 逻辑: MD5( Payload + Salt )
    # Salt 分析: "__       |." (11 chars) + Version ("14.6")
    # 注意: "__       |." 中间是 7 个空格
    salt_part1 = b"__       |." 
    salt_part2 = version
    salt = salt_part1 + salt_part2
    
    hash_input = payload_padded + salt
    
    # 3. 计算 MD5
    m = hashlib.md5()
    m.update(hash_input)
    signature = m.digest() # 16 字节
    
    # 4. 拼接最终文件 (Header + Payload)
    # Header (16 bytes) + Payload (484 bytes) = 500 bytes
    final_data = signature + payload_padded
    
    # 5. 写入文件
    with open(filename, "wb") as f:
        f.write(final_data)
        
    print(f"[-] Successfully generated '{filename}'")
    print(f"    Size: {len(final_data)} bytes (Expected: 500)")
    print(f"    Name: {name}")
    print(f"    Type: {key_type}")
    print(f"    Hash: {signature.hex()}")
    print(f"    Salt used: {salt}")


def decrypt_install_dat(encrypted_data: bytes) -> bytes:
    """
    解密 install.dat 内容
    算法: 异或流密码，密钥随密文滚动更新
    """
    key = INITIAL_KEY
    decrypted = bytearray()
    
    for byte in encrypted_data:
        # 解密当前字节: 明文 = 密文 ^ 密钥
        decrypted_byte = byte ^ key
        decrypted.append(decrypted_byte)
        
        # 更新密钥: 下一个密钥 = 当前密文 + 53
        key = (byte + KEY_MODIFIER) & 0xFF
        
    return bytes(decrypted)

def encrypt_install_dat(plain_data: bytes) -> bytes:
    """
    加密数据以生成 install.dat
    算法: 异或流密码，密钥随密文滚动更新
    """
    key = INITIAL_KEY
    encrypted = bytearray()
    
    for byte in plain_data:
        # 加密当前字节: 密文 = 明文 ^ 密钥
        encrypted_byte = byte ^ key
        encrypted.append(encrypted_byte)
        
        # 更新密钥: 下一个密钥 = 当前密文 + 53 (注意是用密文更新)
        key = (encrypted_byte + KEY_MODIFIER) & 0xFF
        
    return bytes(encrypted)

def calculate_install_dat_signature(payload: bytes) -> bytes:
    """
    计算 Payload 的 MD5 签名
    逻辑: MD5( Payload + "14.6" + "zadf%231d34kjjf" )
    """
    m = hashlib.md5()
    m.update(payload)
    m.update(VERSION)
    m.update(SALT)
    return m.digest()

def create_install_dat_content(payload: bytes) -> bytes:
    """
    生成完整的 install.dat 文件内容 (加密后)
    流程: Payload -> 计算签名 -> 追加签名 -> 加密
    """
    signature = calculate_install_dat_signature(payload)
    full_data = payload + signature
    return encrypt_install_dat(full_data)

def parse_install_dat(file_path: str):
    """
    解析并验证 install.dat 文件
    """
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found.")
        return

    with open(file_path, "rb") as f:
        encrypted_content = f.read()

    print(f"Read {len(encrypted_content)} bytes from {file_path}")

    # 1. 解密
    decrypted_content = decrypt_install_dat(encrypted_content)
    
    if len(decrypted_content) < 16:
        print("Error: File too short to contain signature.")
        return

    # 2. 分离 Payload 和 Signature
    payload = decrypted_content[:-16]
    signature = decrypted_content[-16:]

    print(f"Payload size: {len(payload)} bytes")
    print(f"Signature:    {signature.hex()}")

    # 3. 验证签名
    expected_signature = calculate_install_dat_signature(payload)
    
    if signature == expected_signature:
        print("SUCCESS: Signature verified correctly.")
    else:
        print("WARNING: Signature mismatch!")
        print(f"Calculated:   {expected_signature.hex()}")

    return payload

def generate_install_dat():
    """
    生成一个测试用的 install.dat
    结构: [Count (4 bytes)] + [ID (4 bytes)]...
    """
    # 构造 Payload: 包含 1 个 ID (例如 12345678)
    # 格式: Count(1) + ID(12345678) + Flags(1, 0) (根据之前的代码分析推测)
    
    payload = bytearray()
    install_type = 2 # 0 = 普通安装, 2 = 捐赠版安装
    drive = 'C:'
    hwid = None
    disk_num = get_physical_drive_number(drive)
    if disk_num is not None:
        print(f"Physical Drive Number: {disk_num}")
        serial = get_hard_disk_serial(disk_num)
        if serial:
            print(f"Serial Number: {serial}")
            hwid = zlib.crc32(serial.encode('utf-8')) & 0xFFFFFFFF
            print(f"Calculated HWID (CRC32): 0x{hwid:08X}")
        else:
            print("Failed to retrieve serial number.")
            return
    else:
        print("Failed to get physical drive number.")
        return
    hwid_list = [hwid, hwid]
    extra_data = 0x12345678  # 示例额外数据
    
    payload += struct.pack("<b", install_type)          # Install Type = 0
    payload += struct.pack("<I", len(hwid_list))          # List Items = 1
    
    for hwid in hwid_list:
        payload += struct.pack("<I", hwid)          # HWID
    
    if extra_data is None:
        payload += struct.pack("<b", 0)
    else:
        payload += struct.pack("<b", 1)
        payload += struct.pack("<I", extra_data)
    
    encrypted_content = create_install_dat_content(payload)
    
    with open("Install.dat", "wb") as f:
        f.write(encrypted_content)
    
    print("[-] Generated Install.dat.")



def get_physical_drive_number(drive_letter):
    """
    Get the physical drive number for a given drive letter (e.g., 'C:')
    """
    drive_letter = drive_letter.strip().upper()
    if drive_letter.endswith('\\'):
        drive_letter = drive_letter[:-1]
    if len(drive_letter) == 1:
        drive_letter += ':'
        
    # Open the volume
    volume_path = f"\\\\.\\{drive_letter}"
    try:
        h_volume = win32file.CreateFile(
            volume_path,
            0,  # No access rights needed for this query
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
            None,
            win32con.OPEN_EXISTING,
            0,
            None
        )
    except win32api.error as e:
        print(f"Error opening volume {volume_path}: {e}")
        return None

    # IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000
    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000
    
    # Output buffer for VOLUME_DISK_EXTENTS
    # DWORD NumberOfDiskExtents;
    # DISK_EXTENT Extents[1];
    # DISK_EXTENT is { DWORD DiskNumber; LARGE_INTEGER StartingOffset; LARGE_INTEGER ExtentLength; }
    # Size = 4 + (4 + 8 + 8) * 1 = 24 bytes minimum
    
    try:
        # Allocate a buffer (enough for a few extents)
        out_buffer = win32file.DeviceIoControl(
            h_volume,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            None,
            1024,
            None
        )
    except win32api.error as e:
        print(f"Error getting disk extents: {e}")
        win32file.CloseHandle(h_volume)
        return None
        
    win32file.CloseHandle(h_volume)
    
    # Parse the output
    # First 4 bytes is NumberOfDiskExtents
    num_extents = struct.unpack('I', out_buffer[:4])[0]
    
    if num_extents > 0:
        # Get the first extent's DiskNumber (offset 8 due to padding/alignment? No, struct is packed usually or 4 byte aligned)
        # C struct:
        # DWORD NumberOfDiskExtents; (4 bytes)
        # padding (4 bytes) on 64-bit? Let's check alignment.
        # DISK_EXTENT is 4 (DiskNumber) + 4 (padding) + 8 (StartingOffset) + 8 (ExtentLength) = 24 bytes
        
        # Actually in Python struct, we can just try to unpack.
        # Let's assume standard alignment.
        # Offset 8 is safe for DiskNumber if we consider the first DWORD.
        # Wait, let's look at the bytes.
        # The struct is:
        # DWORD NumberOfDiskExtents
        # DISK_EXTENT Extents[ANYSIZE_ARRAY]
        
        # DISK_EXTENT:
        # DWORD DiskNumber
        # LARGE_INTEGER StartingOffset
        # LARGE_INTEGER ExtentLength
        
        # So directly after the first 4 bytes should be the first DiskNumber.
        disk_number = struct.unpack('I', out_buffer[8:12])[0] # Usually there is padding after the first DWORD in 64-bit align?
        # Let's try offset 8. If NumberOfDiskExtents is at 0.
        # If compiled for 64-bit, VOLUME_DISK_EXTENTS might have padding.
        # Let's try to be robust.
        
        # Actually, let's just use offset 8. The C++ code often accesses it directly.
        # In the C++ code: `v29 = lpOutBuffer[6]` was for SerialNumber.
        # For DiskExtents:
        # `DWORD2(OutBuffer[0])` was checked. OutBuffer is `_OWORD` (16 bytes).
        # `OutBuffer[0]` is 16 bytes. `DWORD2` is the 3rd DWORD (index 2).
        # So bytes 8-12.
        disk_number = struct.unpack('I', out_buffer[8:12])[0]
        return disk_number
        
    return None

def get_hard_disk_serial(disk_number):
    """
    Get the serial number for a physical disk number.
    """
    physical_drive_path = f"\\\\.\\PhysicalDrive{disk_number}"
    
    try:
        h_drive = win32file.CreateFile(
            physical_drive_path,
            0, 
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
            None,
            win32con.OPEN_EXISTING,
            0,
            None
        )
    except win32api.error as e:
        print(f"Error opening physical drive {physical_drive_path}: {e}")
        return None
        
    # IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
    IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
    
    # STORAGE_PROPERTY_QUERY structure
    # PropertyId = StorageDeviceProperty (0)
    # QueryType = PropertyStandardQuery (0)
    # AdditionalParameters = 0
    storage_property_query = struct.pack('III', 0, 0, 0)
    
    try:
        # Get the descriptor
        out_buffer = win32file.DeviceIoControl(
            h_drive,
            IOCTL_STORAGE_QUERY_PROPERTY,
            storage_property_query,
            1024,
            None
        )
    except win32api.error as e:
        print(f"Error querying storage property: {e}")
        win32file.CloseHandle(h_drive)
        return None
        
    win32file.CloseHandle(h_drive)
    
    # STORAGE_DEVICE_DESCRIPTOR structure
    # DWORD Version;
    # DWORD Size;
    # BYTE  DeviceType;
    # BYTE  DeviceTypeModifier;
    # BOOLEAN RemovableMedia;
    # BOOLEAN CommandQueueing;
    # DWORD VendorIdOffset;
    # DWORD ProductIdOffset;
    # DWORD ProductRevisionOffset;
    # DWORD SerialNumberOffset;
    # ...
    
    # SerialNumberOffset is at offset 24 (6 * 4 bytes)
    serial_number_offset = struct.unpack('I', out_buffer[24:28])[0]
    
    if serial_number_offset == 0:
        return None
        
    # Read the null-terminated string from the offset
    # The buffer contains the struct followed by the strings.
    # We need to slice from serial_number_offset until the first null byte.
    
    serial_bytes = out_buffer[serial_number_offset:]
    null_index = serial_bytes.find(b'\x00')
    if null_index != -1:
        serial_bytes = serial_bytes[:null_index]
        
    return serial_bytes.decode('utf-8').strip()

if __name__ == "__main__":
    # 示例用法

    #parsed_payload = parse_install_dat(dummy_file)
    
    # if parsed_payload:
    #     print(f"Decrypted Payload Hex: {parsed_payload.hex()}")

    generate_install_dat()

    # 生成捐赠版 Key
    generate_registered_dat(name="Cracked", email="Cracked@cracked.com", key_type="donation")