# try text to graph
# python

import re
import graphviz
import os

# Function to read and parse the parsed_functions.txt file
def parse_functions_from_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        file_content = file.read()

    functions = {}
    current_function = None

    # Regular expressions to match function and connected functions
    function_pattern = re.compile(r'Function #(\d+) (.*)')
    connected_function_pattern = re.compile(r'=> Function #(\d+)')

    for line in file_content.splitlines():
        function_match = function_pattern.match(line)
        connected_function_match = connected_function_pattern.search(line)

        if function_match:
            function_number = function_match.group(1)
            function_name = function_match.group(2).strip()
            
            # If no name is found, name the function as "func<function_number>"
            if not function_name:
                function_name = f"func{function_number}"

            current_function = function_number
            functions[current_function] = {"name": function_name, "connections": []}
        elif connected_function_match and current_function:
            connected_function = connected_function_match.group(1)
            functions[current_function]["connections"].append(connected_function)

    return functions

# Recursive function to create a flow diagram for a function and its connections
def create_function_flow_graph(func_num, functions, graph, visited):
    if func_num in visited:
        return
    visited.add(func_num)

    function_name = functions[func_num]["name"]
    graph.node(func_num, f"Function #{func_num}\n{function_name}")

    # Draw edges to connected functions
    for connected_func in functions[func_num]["connections"]:
        connected_name = functions[connected_func]["name"]
        graph.node(connected_func, f"Function #{connected_func}\n{connected_name}")
        graph.edge(func_num, connected_func)
        # Recursively process connected functions
        create_function_flow_graph(connected_func, functions, graph, visited)

# Function to draw the function flow for each function in the file
def draw_function_flows(functions, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for func_num, func_info in functions.items():
        # Skip isolated functions (those with no connections)
        if not func_info["connections"]:
            print(f"Skipping Function #{func_num} as it has no connected functions.")
            continue
        
        graph = graphviz.Digraph(comment=f'Function Flow for #{func_num}')
        visited = set()
        create_function_flow_graph(func_num, functions, graph, visited)
        
        # Save both the dot file and the PNG image
        dot_file = f'{output_dir}/function_flow_{func_num}.dot'
        png_file = f'{output_dir}/function_flow_{func_num}'
        
        graph.save(dot_file)  # Save the .dot file
        graph.render(png_file, format='png')  # Save the .png file
        print(f"Graph for Function #{func_num} saved as {png_file} and {dot_file}")

# Main script execution
file_path = 'parsed_functions.txt'
output_dir = 'function_graphs'

# Parse the parsed_functions.txt file
functions = parse_functions_from_file(file_path)

# Draw the function flow graphs
draw_function_flows(functions, output_dir)

print("All function flow graphs and dot files have been generated.")
