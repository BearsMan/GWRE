import frida
import sys
import csv

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
        file_id = int(message['payload'])
        file_info = file_data.get(file_id, {'hash': 'Unknown', 'type': 'Unknown'})
        with open("file_ids.log", "a") as file:
            file.write(f"[File ID Logged]: {file_id}, Hash: {file_info['hash']}, Type: {file_info['type']}\n")

def main():
    # Start the Gw.exe process
    process = frida.spawn(r"C:\games\Guild Wars\outlook\Guild Wars\Gw.exe")

    # Attach to the process
    session = frida.attach(process)

    # Define the JavaScript code for Frida
    js_code = """
    Interceptor.attach(Module.findBaseAddress('Gw.exe').add(0x739d0), {
        onEnter: function(args) {
            // this.context.edx contains the file ID in the EDX register
            send(this.context.edx.toInt32());
        }
    });
    """

    # Create a script and load it into the process
    script = session.create_script(js_code)

    # Set a message handler for writing file IDs to a file
    script.on('message', on_message)

    # Load the script into the process
    script.load()

    # Resume the process
    frida.resume(process)

    # Keep the script running
    sys.stdin.read()

if __name__ == "__main__":
    main()
