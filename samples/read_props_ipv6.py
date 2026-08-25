import asyncio
import socket
from bacpypes3.pdu import IPv6Address
from bacpypes3.app import Application
from bacpypes3.local.networkport import NetworkPortObject
from bacpypes3.object import DeviceObject
from bacpypes3.apdu import IAmRequest
from bacpypes3.primitivedata import ObjectIdentifier


class ReadPropsApplication(Application):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.found_device = asyncio.Event()
        self.target_address = None
        self.target_id = 826012

    async def do_IAmRequest(self, apdu: IAmRequest) -> None:
        print(f"I-Am from {apdu.pduSource}: {apdu.iAmDeviceIdentifier}")
        if apdu.iAmDeviceIdentifier[1] == self.target_id:
            print(f"Found target device {self.target_id} at {apdu.pduSource}")
            self.target_address = apdu.pduSource
            self.found_device.set()
        await super().do_IAmRequest(apdu)


async def main():
    # settings
    local_ipv6 = "fdab:f50f:2652:2b09:4a6c:31ef:b68f:88e3"
    multicast_group = "ff05::bac0"
    target_device_id = 826012

    device_object = DeviceObject(
        objectIdentifier=("device", 12345),
        objectName="IPv6Reader",
        vendorIdentifier=999,
        maxApduLengthAccepted=1476,
        segmentationSupported="no-segmentation",
    )

    network_port = NetworkPortObject(
        objectIdentifier=("networkPort", 1),
        objectName="NetworkPort-1",
        networkType="ipv6",
        protocolLevel="bacnet-application",
        bacnetIPv6Mode="normal",
        ipv6Address=socket.inet_pton(socket.AF_INET6, local_ipv6),
        ipv6PrefixLength=64,
        bacnetIPv6UDPPort=47808,
        bacnetIPv6MulticastAddress=socket.inet_pton(socket.AF_INET6, multicast_group),
    )

    app = ReadPropsApplication.from_object_list([device_object, network_port])
    print(f"Application started, searching for device {target_device_id}...")

    # Wait for the stack to initialize
    await asyncio.sleep(1)

    # Send Who-Is
    from bacpypes3.apdu import WhoIsRequest
    from bacpypes3.pdu import LocalBroadcast

    # Try broadcast first
    print("Sending broadcast Who-Is...")
    await app.who_is(target_device_id, target_device_id)

    # Try unicast to the address provided by the user
    # target_ipv6 = "fd1f:e49d:733a:c571:cc78:b53c:fbd:c5a9"
    # print(f"Sending unicast Who-Is to {target_ipv6}...")
    # # NOTE: In BACnet/IPv6, we can only send unicast if we know the VMAC.
    # # If we don't, we should send it to the IPv6 address and let the BIPNormal layer
    # # resolve it, but it might not be fully implemented yet.
    # # For now, let's try to send it as a broadcast to the specific target address
    # # which is allowed in Annex U for some operations.
    # who_is = WhoIsRequest(
    #     deviceInstanceRangeLowLimit=target_device_id,
    #     deviceInstanceRangeHighLimit=target_device_id,
    # )
    # who_is.pduDestination = IPv6Address(target_ipv6, port=47808)
    # app.request(who_is)

    try:
        # Wait for the device to be found
        await asyncio.wait_for(app.found_device.wait(), timeout=10)
    except asyncio.TimeoutError:
        print("Device not found within timeout.")
        app.close()
        return

    # Read Object Name
    print(f"Reading objectName from {app.target_address}...")
    try:
        name = await app.read_property(
            app.target_address,
            ObjectIdentifier(f"device,{target_device_id}"),
            "objectName",
        )
        print(f"Device Name: {name}")
    except Exception as e:
        print(f"Error reading device name: {e}")

    # Read Analog Input 1 Present Value
    print(f"Reading analogInput,1 presentValue...")
    try:
        value = await app.read_property(
            app.target_address, ObjectIdentifier("analogInput,1"), "presentValue"
        )
        print(f"Analog Input 1 Value: {value}")
    except Exception as e:
        print(f"Error reading analogInput,1: {e}")

    app.close()


if __name__ == "__main__":
    asyncio.run(main())
