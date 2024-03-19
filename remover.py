def remove_lines_with_string(input_file_path, output_file_path, string_to_remove):
    """
    Removes all lines containing a specific string from a file and writes the result to a new file.

    :param input_file_path: Path to the input file.
    :param output_file_path: Path to the output file.
    :param string_to_remove: String to search for removing corresponding lines.
    """
    with open(input_file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    with open(output_file_path, 'w', encoding='utf-8') as output_file:
        for line in lines:
            if string_to_remove not in line:
                output_file.write(line)


input_file = "output.log"
output_file = "output.log"
string_to_remove = 'pam_unix(cron:session): session closed for user root'
remove_lines_with_string(input_file, output_file, string_to_remove)
