class MarkdownFormatter:
    def __init__(self):
        pass

    @staticmethod
    def extract_strings(list_of_strings):
        strings = ""
        for binary_string in list_of_strings:
            strings += f"{binary_string}\n"

        return strings

    @staticmethod
    def format_info_table(info, *headers):

        if not info:
            return ""

        if not isinstance(info, dict):
            raise TypeError("info must be a dictionary")

        info = list(info.items())
        # top table
        table = "|"
        for header in headers:
            table += f" {header} |"
        table += "\n"
        # dashes
        table += "|"
        for header in headers:
            table += " "
            table += ("-" * len(header))
            table += " |"
        table += "\n"
        # dictionary info
        for row in range(len(info)):

            if len(info[row]) != len(headers):
                raise ValueError("Dictionary Info and Header Mismatch")

            table += "|"
            for col in range(len(info[row])):
                table += f" {info[row][col]} |"
            table += "\n"
        return table
