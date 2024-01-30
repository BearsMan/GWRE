import frida
import sys
import csv
import struct
import json

# Function to convert a float to little-endian byte representation
def float_to_bytes(value):
    return struct.pack('<f', value)

# Convert hex string to byte array, supporting space-separated or continuous hex strings
def hex_string_to_bytes(hex_string):
    hex_string = hex_string.replace(" ", "").replace("\n", " ")  # Remove spaces if any
    return bytes.fromhex(hex_string)

# Load overwrite specifications from a JSON file
def load_json_overwrites(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            overwrites = {}
            for entry in data['overwriteSpecifications']:
                file_id = entry['fileId']
                for action in entry['offsets']:
                    offset = action['offset']
                    record_name = f"{file_id}_{offset}_{action['recordName']}"  # Include recordName in the key
                    overwrites[record_name] = {
                        'file_id': file_id,
                        'offset': int(offset, 16),
                        'data': hex_string_to_bytes(action['data']),
                        'enabled': action.get('enabled', True)  # Default to enabled if not specified
                    }
        return overwrites
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        return {}  # Return an empty dictionary or handle as needed
    except json.JSONDecodeError:
        print(f"Error: There was a syntax error in the JSON file '{file_path}'.")
        return {}  # Return an empty dictionary or handle as needed


# Dictionary to hold multiple overwrite records
overwrite_records = {
    'record1': {
        'file_id': '0x1B97D',  # File ID for this record
        'offset': 0x359C1,  # Position in the decompressed file to overwrite
        'data': float_to_bytes(-3300.0) * (0xD0000 // 4),  # Overwrite data
        'enabled': True  # Whether this overwrite is active
    },
    # Add more records as needed
}

# Load overwrites from JSON file and merge with existing records
overwrite_records.update(load_json_overwrites('./data/gw_dat_mod.json'))

# Function to load the data from the CSV file into a dictionary
def load_file_data(filename):
    data_dict = {}
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            data_dict[int(row['file_id'])] = {'hash': row['murmur3hash'], 'type': row['file_type']}
    return data_dict

# Load the file data into a dictionary
file_data = load_file_data('data/file_data.csv')

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if isinstance(payload, dict) and 'file_id' in payload:
            file_id = payload['file_id']
            file_info = file_data.get(int(file_id, 16), {'hash': 'Unknown', 'type': 'Unknown'})
            print(f"File ID: {file_id}, Hash: {file_info['hash']}, Type: {file_info['type']}")
            if 'existingData' in payload:
                print("Existing Data:", ' '.join(f'{b:02x}' for b in payload['existingData']))
        else:
            print(payload)

def main():
    process = frida.spawn(r"C:\games\Guild Wars\outlook\Guild Wars\Gw.exe")
    session = frida.attach(process)

    js_code_parts = []
    for name, record in overwrite_records.items():
        if record['enabled']:
            js_code_parts.append(f"""
            if (this.file_id === {int(record['file_id'], 16)}) {{
                const targetAddress = retval.add({record['offset']});
                var existingData = Memory.readByteArray(targetAddress, {len(record['data'])});
                send({{ 'file_id': '0x' + this.file_id.toString(16), 'existingData': Array.from(new Uint8Array(existingData)) }});
                Memory.writeByteArray(targetAddress, [{', '.join(f'0x{b:02x}' for b in record['data'])}]);
            }}
            """)

    js_code = """
    const decompressFunc = Module.findBaseAddress('Gw.exe').add(0x74180);

    Interceptor.attach(decompressFunc, {{
        onEnter: function(args) {{
            this.file_id = args[0].toInt32();
        }},
        onLeave: function(retval) {{
            {0}
        }}
    }});
    """.format(''.join(js_code_parts))

    script = session.create_script(js_code)
    script.on('message', on_message)
    script.load()
    frida.resume(process)
    sys.stdin.read()

if __name__ == "__main__":
    main()
