from sanitize import escape_query
from db import search_raw, search_safe


def handle_search(request):
    query = request.args.get('q', '')
    results_unsafe = search_raw(query)
    clean = escape_query(query)
    results_safe = search_safe(clean)
    return results_unsafe + results_safe
