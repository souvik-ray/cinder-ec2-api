from ec2api.api.temp import SyncFlowMetricsWrapper
 
# Wrapper for Cinder Volume
class Ec2APIMetricsWrapper(SyncFlowMetricsWrapper):
    def __init__(self, operation_name):
        super(Ec2APIMetricsWrapper, self).__init__("Ec2API", "/var/log/ec2api/service.log")
