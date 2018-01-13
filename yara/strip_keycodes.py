import argparse, re

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Strips keycodes from rtf data (used for obfuscation in many maldocs).")
    parser.add_argument("-i", "--input", help="Input file", required=True)
    parser.add_argument('-o', "--output", help="Output file", required=True)

    args = parser.parse_args()

    with open(args.input, 'r') as f:
    	in_rtf = f.read()

    with open(args.output, 'w') as f:
        f.write(re.sub(r"(?:\{\\\*\\keycode[0-9]+ {1})([0-9a-fA-F]+)\}",r"\1", in_rtf))
    
    print "[+] Done!"