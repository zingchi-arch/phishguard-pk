"""Simple console interface: python check_message.py 'message here'"""
import json,sys
from phishguard.inference import analyze_message
if __name__=='__main__':
    if len(sys.argv)<2:
        print('Usage: python check_message.py "Paste a sample message"')
        sys.exit(2)
    print(json.dumps(analyze_message(' '.join(sys.argv[1:])),indent=2,ensure_ascii=False))
