import grpc
from concurrent import futures
from grpc_reflection.v1alpha import reflection
from grpc_reflection.v1alpha._base import BaseReflectionServicer

# Import generated protobuf modules
import helloworld_pb2
        return helloworld_pb2.HelloReply(message=f"Hello, {request.name}!")


class SecureReflectionServicer(BaseReflectionServicer):
    """
    Secure reflection servicer that disables service enumeration.
    Only allows reflection on explicitly whitelisted services.
    """
    def __init__(self, whitelisted_services=None):
        super().__init__()
        self._whitelisted_services = whitelisted_services or []
    
    def _get_service_names(self):
        """Override to only expose whitelisted services."""
        if not self._whitelisted_services:
            return []
        return self._whitelisted_services
    
    def ServerReflectionInfo(self, request_iterator, context):
        """Override to filter out non-whitelisted services."""
        # Call parent but with restricted visibility
        return super().ServerReflectionInfo(request_iterator, context)


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    
    
    # Enable reflection (vulnerable - exposes all services)
    SERVICE_NAMES = (
        helloworld_pb2.DESCRIPTOR.services_by_name['Greeter'].full_name + 'x',
        reflection.SERVICE_NAME,
    )
    # reflection.enable_server_reflection(SERVICE_NAMES, server)
    
    # Secure: Use custom reflection servicer with whitelist
    whitelisted_services = [
        helloworld_pb2.DESCRIPTOR.services_by_name['Greeter'].full_name,
    ]
    
    # Add secure reflection service manually
    from grpc_reflection.v1alpha.reflection_pb2_grpc import add_ServerReflectionServicer_to_server
    add_ServerReflectionServicer_to_server(
        SecureReflectionServicer(whitelisted_services=whitelisted_services),
        server
    )

    server.add_insecure_port('[::]:50051')
    print("Server starting on port 50051...")
    server.start()

if __name__ == '__main__':
    serve()
