import grpc
from concurrent import futures
import your_service_pb2
import your_service_pb2_grpc

class YourService(your_service_pb2_grpc.YourServiceServicer):
    def SomeMethod(self, request, context):
        return your_service_pb2.SomeResponse(message='Hello, %s!' % request.name)

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    your_service_pb2_grpc.add_YourServiceServicer_to_server(YourService(), server)
    
    # Disable reflection
    # from grpc_reflection.v1alpha import reflection
    # SERVICE_NAMES = (
    #     your_service_pb2.DESCRIPTOR.services_by_name['YourService'].full_name,
    #     reflection.SERVICE_NAME,
    # )
    # reflection.enable_server_reflection(SERVICE_NAMES, server)
    
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()

if __name__ == '__main__':
    serve()