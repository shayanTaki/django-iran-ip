from django_iran_ip.core.resolver import IPResolver

def get_client_ip(request) -> str:

    resolver = IPResolver()
    return resolver.get_client_ip(request)