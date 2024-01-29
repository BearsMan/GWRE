import frida
import sys
import csv
import struct

target_file_id = '0x1B97D'

# Convert the float -1000 to a little-endian byte representation
float_bytes = struct.pack('<f', -100000.0)

# overwrite_bytes = [0xFF, 0x00, 0x00]  # Bytes to overwrite with
overwrite_bytes = float_bytes * (0xD0000 // 4)
overwrite_bytes = [1,2,3,4] * (0x34000 // 4)

N = len(overwrite_bytes)  # Number of bytes to overwrite
X = 0x359C1  # Position in the decompressed file to overwrite
X = 0x1059C6

# Function to load the data from the CSV file into a dictionary
def load_file_data(filename):
    data_dict = {}
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            data_dict[int(row['file_id'], 16)] = {'hash': row['murmur3hash'], 'type': row['file_type']}
    return data_dict


# Load the file data into a dictionary
file_data = load_file_data('data/file_data.csv')


def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if isinstance(payload, dict) and 'file_id' in payload:
            file_id = payload['file_id']
            if file_id.lower() == target_file_id.lower():
                file_info = file_data.get(int(file_id, 16), {'hash': 'Unknown', 'type': 'Unknown'})
                print(f"File ID: {file_id}, Hash: {file_info['hash']}, Type: {file_info['type']}")
                if 'existingData' in payload:
                    print("Existing Data:", ' '.join(f'{b:02x}' for b in payload['existingData']))
        else:
            print(payload)


def main():
    # Start the Gw.exe process
    process = frida.spawn(r"C:\games\Guild Wars\outlook\Guild Wars\Gw.exe")

    # Attach to the process
    session = frida.attach(process)

    # Define the JavaScript code for Frida, incorporating Python variables
    js_code = f"""
    const targetFileId = parseInt('{target_file_id}');
    const decompressFunc = Module.findBaseAddress('Gw.exe').add(0x74180);
    const N = {N};
    const X = {X};
    const overwriteBytes = [{', '.join(f'0x{b:02x}' for b in overwrite_bytes)}];

    Interceptor.attach(decompressFunc, {{
        onEnter: function(args) {{
            this.file_id = args[0].toInt32();
            this.overwrite = (this.file_id === targetFileId);
            if (this.overwrite) {{
                send({{ 'file_id': '0x' + this.file_id.toString(16) }});
            }}
        }},
        onLeave: function(retval) {{
            if (!this.overwrite) return;

            const targetAddress = retval.add(X);
            var existingData = Memory.readByteArray(targetAddress, N);
            send({{ 'file_id': '0x' + this.file_id.toString(16), 'existingData': Array.from(new Uint8Array(existingData)) }});

            Memory.writeByteArray(targetAddress, overwriteBytes);
        }}
    }});
    """

    # Create a script and load it into the process
    script = session.create_script(js_code)

    # Set a message handler
    script.on('message', on_message)

    # Load the script into the process
    script.load()

    # Resume the process
    frida.resume(process)

    # Keep the script running
    sys.stdin.read()


if __name__ == "__main__":
    main()
