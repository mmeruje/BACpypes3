"""
Link Layer Module
"""

from __future__ import annotations
from typing import List, Optional

from ..debugging import bacpypes_debugging, ModuleLogger
from ..comm import bind
from ..pdu import IPv6Address, VirtualAddress
from ..ipv6 import IPv6DatagramServer
from .bvll import BVLLCodec
from .service import BIPNormal, BIPForeign, BIPBBMD, BVLLServiceElement

# some debugging
_debug = 0
_log = ModuleLogger(globals())

@bacpypes_debugging
class NormalLinkLayer(BIPNormal):
    """
    Create a link layer mini-stack starting with the "normal"
    BVLLServiceAccessPoint (parent class of BIPNormal) down to the datagram
    server.
    """

    codec: BVLLCodec
    server: IPv6DatagramServer
    ase: BVLLServiceElement

    def __init__(
        self,
        local_address: IPv6Address,
        virtual_address: VirtualAddress,
        multicast_groups: Optional[List[str]] = None,
        **kwargs,
    ) -> None:
        if _debug:
            NormalLinkLayer._debug(
                "__init__ %r %r %r %r",
                local_address,
                virtual_address,
                multicast_groups,
                kwargs,
            )
        BIPNormal.__init__(self, virtual_address=virtual_address, **kwargs)

        self.codec = BVLLCodec()
        self.server = IPv6DatagramServer(local_address, multicast_groups=multicast_groups)
        self.ase = BVLLServiceElement()

        bind(self, self.codec, self.server)
        bind(self.ase, self)

    def close(self):
        if _debug:
            NormalLinkLayer._debug("close")
        self.server.close()

@bacpypes_debugging
class ForeignLinkLayer(BIPForeign):
    """
    Create a link layer mini-stack starting with the "foreign"
    BVLLServiceAccessPoint (parent class of BIPForeign) down to the datagram
    server.
    """

    codec: BVLLCodec
    server: IPv6DatagramServer
    ase: BVLLServiceElement

    def __init__(
        self,
        local_address: IPv6Address,
        virtual_address: VirtualAddress,
        **kwargs,
    ) -> None:
        if _debug:
            ForeignLinkLayer._debug(
                "__init__ %r %r %r",
                local_address,
                virtual_address,
                kwargs,
            )
        BIPForeign.__init__(self, virtual_address=virtual_address, **kwargs)

        self.codec = BVLLCodec()
        self.server = IPv6DatagramServer(local_address)
        self.ase = BVLLServiceElement()

        bind(self, self.codec, self.server)
        bind(self.ase, self)

    def close(self):
        if _debug:
            ForeignLinkLayer._debug("close")
        self.server.close()

@bacpypes_debugging
class BBMDLinkLayer(BIPBBMD):
    """
    Create a link layer mini-stack starting with the BBMD
    BVLLServiceAccessPoint (parent class of BIPBBMD) down to the datagram
    server.
    """

    codec: BVLLCodec
    server: IPv6DatagramServer
    ase: BVLLServiceElement

    def __init__(
        self,
        local_address: IPv6Address,
        virtual_address: VirtualAddress,
        **kwargs,
    ) -> None:
        if _debug:
            BBMDLinkLayer._debug(
                "__init__ %r %r %r",
                local_address,
                virtual_address,
                kwargs,
            )
        BIPBBMD.__init__(self, local_address, virtual_address=virtual_address, **kwargs)

        self.codec = BVLLCodec()
        self.server = IPv6DatagramServer(local_address)
        self.ase = BVLLServiceElement()

        bind(self, self.codec, self.server)
        bind(self.ase, self)

    def close(self):
        if _debug:
            BBMDLinkLayer._debug("close")
        self.server.close()
