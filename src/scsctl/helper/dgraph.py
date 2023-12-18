import pydgraph

def connect_local(host='localhost', port=9080):
    client_stub = pydgraph.DgraphClientStub(f'{host}:{port}')
    return pydgraph.DgraphClient(client_stub), client_stub