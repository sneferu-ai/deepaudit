import sys
sys.path.insert(0, "/repo")
import app

class _MockArgs:
    @staticmethod
    def get(name, default=''):
        if name == 'q':
            return "' UNION SELECT 'DA-FwS4zNwaLNs9dOw59D1x21F3', NULL --"
        return default

class _MockRequest:
    args = _MockArgs()

try:
    result = app.handle_search(_MockRequest())
    if 'DA-FwS4zNwaLNs9dOw59D1x21F3' in str(result):
        print('DA-FwS4zNwaLNs9dOw59D1x21F3')
        sys.exit(0)
except Exception as e:
    print('ERROR:', e)
    pass
print('__HARNESS_DONE__')
