# parse to text
# python
import re

# Function to parse the hasm file for function details and connected functions
def parse_hasm_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        file_content = file.read()

    # Regular expression to match main function definitions
    function_pattern = re.compile(r'\[Function #(\d+) "(.*?)" of \d+ bytes\]')

    # Regular expression to match all connected functions within the bytecode
    connected_function_pattern = re.compile(r'# Function: \[#(\d+)')

    # Split the content into individual function sections by the "==============" divider
    function_sections = file_content.split('===============\n')

    parsed_functions = []

    # Parse each section for function number, name, and connected functions
    for section in function_sections:
        # Look for the main function number and name
        main_function_match = function_pattern.search(section)
        if main_function_match:
            function_number = main_function_match.group(1)
            function_name = main_function_match.group(2)

            # Find all connected functions within this section
            connected_functions = connected_function_pattern.findall(section)

            # Store the parsed data as a tuple
            parsed_functions.append({
                "function_number": function_number,
                "function_name": function_name,
                "connected_functions": connected_functions
            })

    return parsed_functions

# Function to write the parsed functions and their connections to a text file
def write_parsed_functions_to_file(parsed_functions, output_file_path):
    with open(output_file_path, 'w', encoding='utf-8') as file:
        for func in parsed_functions:
            file.write(f"Function #{func['function_number']} {func['function_name']}\n")
            if func['connected_functions']:
                for connected_func in func['connected_functions']:
                    file.write(f"  => Function #{connected_func}\n")
            else:
                file.write("  => No connected functions\n")
            file.write("\n")

# Path to your hasm file
file_path = 'my_output_file.hasm'

# Path to the output text file where the result will be saved
output_file_path = 'parsed_functions.txt'

# Parse the hasm file
parsed_functions = parse_hasm_file(file_path)

# Write the parsed functions and their connections to a text file
write_parsed_functions_to_file(parsed_functions, output_file_path)

print(f"Results written to {output_file_path}")
