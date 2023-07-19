# Manuel Eggimann <meggimann@iis.ee.ethz.ch>
#
# Copyright (C) 2020-2022 ETH Zürich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" Provides the ``RISCVDebugTap`` class for high level interaction with RISC-V debug spec compliant JTAG debug transport modules.

In order to use the ``RISCVDebugTap``, you will have to instantiate it and register it with your ``JTAGDriver`` instance.
See the documentation of ``JTAGDriver`` for an example.

"""

import re
from enum import Enum
from typing import List, Literal, Optional, Union, overload

import bitstring
from bitstring import BitArray
from dumpling.Common.Utilities import pp_binstr
from dumpling.Common.VectorBuilder import NormalVector, Vector, VectorBuilder
from dumpling.Drivers.JTAG import JTAGDriver, JTAGRegister, JTAGTap

bitstring.lsb0 = True  # Enables the experimental mode to index LSB with 0 instead of the MSB (see thread https://github.com/scott-griffiths/bitstring/issues/156)


class DMIOp(Enum):
    NOP = "00"
    READ = "01"
    WRITE = "10"


class DMIResult(Enum):
    OP_SUCCESS = "00"
    OP_FAILED = "10"
    OP_PENDING = "11"


class DMRegAddress(Enum):
    NO_REG = f"{0x00:0>7b}"
    DATAO = f"{0x04:0>7b}"
    DATA11 = f"{0x0f:0>7b}"
    DMCONTROL = f"{0x10:0>7b}"
    DMSTATUS = f"{0x11:0>7b}"
    HARTINFO = f"{0x12:0>7b}"
    HALTSUM1 = f"{0x13:0>7b}"
    HAWINDOWSEL = f"{0x14:0>7b}"
    HAWINDOW = f"{0x15:0>7b}"
    ABSTRACTCS = f"{0x16:0>7b}"
    COMMAND = f"{0x17:0>7b}"
    ABSTRACTAUTO = f"{0x18:0>7b}"
    CONFSTRPTR0 = f"{0x19:0>7b}"
    CONFSTRPTR1 = f"{0x1a:0>7b}"
    CONFSTRPTR2 = f"{0x1b:0>7b}"
    CONFSTRPTR3 = f"{0x1c:0>7b}"
    NEXTDM = f"{0x1d:0>7b}"
    PROGBUF0 = f"{0x20:0>7b}"
    PROGBUF15 = f"{0x2f:0>7b}"
    AUTHDATA = f"{0x30:0>7b}"
    HALTSUM2 = f"{0x34:0>7b}"
    HALTSUM3 = f"{0x35:0>7b}"
    SBADDRESS3 = f"{0x37:0>7b}"
    SBCS = f"{0x38:0>7b}"
    SBADDRESS0 = f"{0x39:0>7b}"
    SBADDRESS1 = f"{0x3a:0>7b}"
    SBADDRESS2 = f"{0x3b:0>7b}"
    SBDATA0 = f"{0x3c:0>7b}"
    SBDATA1 = f"{0x3d:0>7b}"
    SBDATA2 = f"{0x3e:0>7b}"
    SBDATA3 = f"{0x3f:0>7b}"
    HALTSUM0 = f"{0x40:0>7b}"


class RISCVReg(Enum):
    # Floating-Point CSRs
    CSR_FFLAGS = "0x001"
    CSR_FRM = "0x002"
    CSR_FCSR = "0x003"
    CSR_FTRAN = "0x800"
    # Supervisor Mode CSRs
    CSR_SSTATUS = "0x100"
    CSR_SIE = "0x104"
    CSR_STVEC = "0x105"
    CSR_SCOUNTEREN = "0x106"
    CSR_SSCRATCH = "0x140"
    CSR_SEPC = "0x141"
    CSR_SCAUSE = "0x142"
    CSR_STVAL = "0x143"
    CSR_SIP = "0x144"
    CSR_SATP = "0x180"
    # Machine Mode CSRs
    CSR_MSTATUS = "0x300"
    CSR_MISA = "0x301"
    CSR_MEDELEG = "0x302"
    CSR_MIDELEG = "0x303"
    CSR_MIE = "0x304"
    CSR_MTVEC = "0x305"
    CSR_MCOUNTEREN = "0x306"
    CSR_MSCRATCH = "0x340"
    CSR_MEPC = "0x341"
    CSR_MCAUSE = "0x342"
    CSR_MTVAL = "0x343"
    CSR_MIP = "0x344"
    CSR_PMPCFG0 = "0x3A0"
    CSR_PMPADDR0 = "0x3B0"
    CSR_MVENDORID = "0xF11"
    CSR_MARCHID = "0xF12"
    CSR_MIMPID = "0xF13"
    CSR_MHARTID = "0xF14"
    CSR_MCYCLE = "0xB00"
    CSR_MINSTRET = "0xB02"
    CSR_DCACHE = "0x701"
    CSR_ICACHE = "0x700"

    CSR_TSELECT = "0x7A0"
    CSR_TDATA1 = "0x7A1"
    CSR_TDATA2 = "0x7A2"
    CSR_TDATA3 = "0x7A3"
    CSR_TINFO = "0x7A4"

    # Debug CSR
    CSR_DCSR = "0x7b0"
    CSR_DPC = "0x7b1"
    CSR_DSCRATCH0 = "0x7b2"  # optional
    CSR_DSCRATCH1 = "0x7b3"  # optional

    # Counters and Timers
    CSR_CYCLE = "0xC00"
    CSR_TIME = "0xC01"
    CSR_INSTRET = "0xC02"
    # Performance counters
    CSR_L1_ICACHE_MISS = "0xC03"  # L1 Instr Cache Miss
    CSR_L1_DCACHE_MISS = "0xC04"  # L1 Data Cache Miss
    CSR_ITLB_MISS = "0xC05"  # ITLB Miss
    CSR_DTLB_MISS = "0xC06"  # DTLB Miss
    CSR_LOAD = "0xC07"  # Loads
    CSR_STORE = "0xC08"  # Stores
    CSR_EXCEPTION = "0xC09"  # Taken exceptions
    CSR_EXCEPTION_RET = "0xC0A"  # Exception return
    CSR_BRANCH_JUMP = "0xC0B"  # Software change of PC
    CSR_CALL = "0xC0C"  # Procedure call
    CSR_RET = "0xC0D"  # Procedure Return
    CSR_MIS_PREDICT = "0xC0E"  # Branch mis-predicted
    CSR_SB_FULL = "0xC0F"  # Scoreboard full
    CSR_IF_EMPTY = "0xC10"  # instruction fetch queue empty

    def to_bits(self) -> BitArray:
        return bitstring.pack("hex:12, 0x0", self.value)


class DMAbstractCmdType(Enum):
    ACCESS_REG = 0
    QUICK_ACCESS = 1
    ACCESS_MEM = 2

    def to_bits(self) -> BitArray:
        return BitArray(uint=self.value, length=8)  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed


class DMAbstractCmd:
    def __init__(
        self,
        cmd_type: "DMAbstractCmdType",
        reg: "RISCVReg",
        write: bool = False,
        transfer: bool = False,
        postexec: bool = False,
        aarpostinc: bool = False,
        aarsize: int = 2,
    ):
        # Validate Input
        if aarsize not in [2, 3, 4]:
            raise ValueError("Illegal aarsize: {}".format(aarsize))
        self.reg = reg
        self.write = write
        self.transfer = transfer
        self.postexec = postexec
        self.aarpostinc = aarpostinc
        self.aarsize = aarsize
        self.cmd_type = cmd_type

    def to_bits(self) -> BitArray:
        return bitstring.pack(
            "bits, bool, bool, bool, bool, uint:3, 0b0, bits",
            self.reg.to_bits(),
            self.write,
            self.transfer,
            self.postexec,
            self.aarpostinc,
            self.aarsize,
            self.cmd_type.to_bits(),
        )


class RISCVDebugTap(JTAGTap):
    """A JTAG Tap implementation for the RISC-V JTAG Debug Transport Module
    
    This class implements functions to interact with a RISC-V debug
    specification compliant debug module. It has been tested with the PULP
    implementation of the debug module.
    """
    
    def __init__(self, driver: JTAGDriver, idcode: str = "0x249511C3"):
        super().__init__("RISC-V debug module", 5, driver)
        # Add JTAG registers
        self.reg_soc_idcode = self._add_reg(
            JTAGRegister("SoC IDCODE", "00001", 32, BitArray(idcode).bin)
        )
        self.reg_soc_dtmcsr = self._add_reg(JTAGRegister("SoC DTMCSR", "10000", 32))
        self.reg_soc_dmiaccess = self._add_reg(
            JTAGRegister("SoC DMIACCESS", "10001", 41)
        )

    def verify_idcode(self) -> List[NormalVector]:
        """Selects the IDCODE register of this tap (all other TAPs are put into bypass mode) and verifies that IDCODE
        matches the expected value."""
        return self.reg_soc_idcode.read(
            expected_value=self.reg_soc_idcode.default_value,
            comment="Verifying IDCODE of RISC-V Debug Unit",
        )

    def init_dmi(self) -> List[NormalVector]:
        """Initialize the debug module interface by setting this TAP's IR to the DMIACCESS register.

        Returns:
            List[NormalVector]: The generated vectors
        """
        return self.driver.jtag_set_ir(
            self,
            self.reg_soc_dmiaccess.IR_value,
            comment="Init DMIACCESS (set corresponding IR)",
        )

    def set_dmi(
        self,
        dm_op: DMIOp,
        dmi_addr: DMRegAddress,
        new_dm_data: str,
        expected_dm_status: Optional[DMIResult] = None,
        expected_dm_data: Optional[str] = None,
        comment: Optional[str] = None,
    ) -> List[NormalVector]:
        """Start a DMIACCESS operation

        Perform a read or write operation to one of the DM's registers through the DMIACCESS JTAG register. 

        Args:
            dm_op (DMIOp): The operation to perform
            dmi_addr (DMRegAddress): The DM register to access
            new_dm_data (str): Data to be written into the DM register
            expected_dm_status (Optional[DMIResult], optional): The (optional) expected status of the status bits when
                shifting out DMACCESS. Use the letter 'x' for don't care bits.. Defaults to None.
            expected_dm_data (Optional[str], optional): The (optional) expected data of the shifted out from DMACCESS.
                Use the letter 'x' for don't care bits.  Defaults to None.
            comment (Optional[str], optional): An optional comment to provide context for this vector. Defaults to None.

        Returns:
            List[NormalVector]: The generated vectors
        """
        if comment is None:
            comment = ""
        comment += "/Start DMI access with OP {} to register {}.".format(
            dm_op, dmi_addr.name
        )
        if expected_dm_status and expected_dm_data:
            comment += " Expecting status {} and data 0b{}".format(
                expected_dm_status, expected_dm_data
            )
        dr_value = dmi_addr.value + new_dm_data + dm_op.value
        expected_dr_value = 8 * "X"
        expected_dr_value += expected_dm_data if expected_dm_data else 32 * "X"
        expected_dr_value += expected_dm_status.value if expected_dm_status else "XX"
        return self.driver.jtag_set_dr(self, dr_value, expected_dr_value, comment)

    def wait_command(
        self, retries: int = 1, comment: Optional[str] = None
    ) -> List[Vector]:
        """Wait for a previous DMIACCESS command to complete

        Args:
            retries (int, optional): The number of retires in the matched loop before the access is considered to have failed. Defaults to 1.
            comment (Optional[str], optional): An optional comment to provide context. Defaults to None.

        Returns:
            List[Vector]: The generated vectors
        """
        if comment is None:
            comment = ""
        comment += "/Wait for abstract command completion"
        expected_abstractcs: BitArray = BitArray(32)  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
        mask: BitArray = BitArray(32)  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
        expected_abstractcs[12] = 0
        mask[12] = 1
        expected_abstractcs[8:11] = "0b000"
        mask[8:11] = "0b111"

        expected_abstractcs_value = ""
        # Iterate over bits LSB-first
        for bit, maskbit in zip(expected_abstractcs, mask):  # type: ignore
            if maskbit:
                expected_abstractcs_value += str(int(bit))
            else:
                expected_abstractcs_value += "X"
        # Reverse the order since read_debug_reg expects data in MSB-to-LSB order
        expected_abstractcs_value = expected_abstractcs_value[::-1]
        return self.read_debug_reg(
            DMRegAddress.ABSTRACTCS, expected_abstractcs_value, retries, comment=comment
        )

    def set_command_no_loop(
        self, cmd: DMAbstractCmd, comment: Optional[str] = None, wait_cycles: int = 10
    ) -> List[NormalVector]:
        if comment is None:
            comment = ""
        comment += "/Issue abstract command register"
        # Write to command register
        vectors = self.write_debug_reg(
            DMRegAddress.COMMAND,
            cmd.to_bits().bin,
            verify_completion=False,
            comment=comment,
        )
        # Wait for completion of the command
        vectors += [
            self.driver.jtag_idle_vector(
                repeat=wait_cycles, comment="Waiting for command completion"
            )
        ]
        return vectors

    def set_command(
        self, cmd: DMAbstractCmd, comment: Optional[str] = None, retries: int = 1
    ) -> List[Vector]:
        if comment is None:
            comment = ""
        comment += "/Issue abstract command register"
        # Write to command register
        vectors = self.write_debug_reg(
            DMRegAddress.COMMAND,
            cmd.to_bits().bin,
            verify_completion=False,
            comment=comment,
        )
        # Wait for completion of the command
        vectors += self.wait_command(retries)
        return vectors

    def dmi_reset(self) -> List[NormalVector]:
        """Reset the debug interface by asserting the debug reset flag in the DTMCS register.

        Returns:
            List[NormalVector]: The generated vectors
        """
        dr_value: BitArray = BitArray(32)  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
        dr_value[16] = 1
        dr_value = dr_value.bin
        vectors = self.driver.write_reg(
            self, self.reg_soc_dtmcsr, dr_value, "Reset DMI"  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
        )
        vectors += self.init_dmi()  # Change IR back to DMIACCESS register
        return vectors

    def dmi_hardreset(self) -> List[NormalVector]:
        """Hard reset the SoC asserting the hardreset flag in the DTMCS register.

        This only works, if the debug module's hard reset line is actually connected to the SoC's reset generation logic (not the case in many PULP chips).

        Returns:
            List[NormalVector]: The generated vectors
        """
        dr_value: BitArray = BitArray(32)  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
        dr_value[17] = 1
        value: str = dr_value.bin
        return self.driver.jtag_set_dr(self, value, "Hardreset DMI")

    def set_dmactive(self, dmactive: bool) -> List[NormalVector]:
        """Enable/Disable the debug module by setting the DMACTIVE bit in the DMCONTROL register.

        Args:
            dmactive (bool): `True` to enable the debug module, `False` to disable it.

        Returns:
            List[NormalVector]: The generated vectors
        """
        return self.set_dmi(
            DMIOp.WRITE,
            DMRegAddress.DMCONTROL,
            31 * "0" + "1" if dmactive else "0",
            comment="Set DMACTIVE flag",
        )

    def read_debug_reg_no_loop(
        self,
        dmi_addr: DMRegAddress,
        expected_data: str,
        wait_cycles: int = 0,
        comment: Optional[str] = None,
    ) -> List[NormalVector]:
        """Read from a debug reg through a DMIACCESS command without using matched loop vectors.

        This command just waits for the configured number of ``wait_cycles`` for the DMIACCESS operation to complete. If
        the operation takes longer than that, the busy error flag will be asserted when checking the DMI status and the
        operation will be considered failing. If the vectors fail for your chip, try increasing the wait cycles.

        Args:
            dmi_addr (DMRegAddress): The DM register to read from.
            expected_data (str): The expected read data to match. Use the letter 'x' for don't care bits.
            wait_cycles (int, optional): The number of cycles to wait for the read operation to complete. Defaults to 0.
            comment (Optional[str], optional): An optional comment to provide context. Defaults to None.

        Returns:
            List[NormalVector]: The generated vectors
        """
        if comment is None:
            comment = ""
        comment += "/Verify debug reg {} to be 0b{}.".format(dmi_addr, expected_data)

        # Generate vectors to start read operation from register
        vectors = self.set_dmi(DMIOp.READ, dmi_addr, 32 * "0", comment=comment)
        self.driver.set_jtag_default_values()
        self.driver.vector_builder.tck = 1
        vectors += [
            self.driver.vector_builder.vector(
                repeat=10,
                comment="Clock tck for a few cycles to let dmi complete operation",
            )
        ]
        # Don't use a matched loop but wait for a couple of jtag cycles before trying to read the DMIACCESS register
        vectors += [
            self.driver.jtag_idle_vector(
                repeat=wait_cycles, comment="Waiting for completion of DMI read OP."
            )
        ]
        vectors += self.set_dmi(
            DMIOp.NOP,
            DMRegAddress.NO_REG,
            32 * "0",
            DMIResult.OP_SUCCESS,
            expected_data,
        )
        return vectors

    def read_debug_reg(
        self,
        dmi_addr: DMRegAddress,
        expected_data: str,
        retries: int = 1,
        comment: Optional[str] = None,
    ) -> List[Vector]:
        """Read from a debug register using a DMIACCESS operation.

        This version of the function uses a matched loop to wait for the read operation to complete. If this is undesired,
        use the ``read_debug_reg_no_loop`` function instead, which just waits for a user configurable number of JTAG idle cycles.

        Args:
            dmi_addr (DMRegAddress): The DM register to read from
            expected_data (str): The expected read data to match. Use the letter 'x' for don't care bits.
            retries (int, optional): The number of polls on the status bit before considering the read operation to have failed. Defaults to 1.
            comment (Optional[str], optional): An optional comment to provide context. Defaults to None.

        Returns:
            List[Vector]: The generated vectors.
        """
        if comment is None:
            comment = ""
        comment += "/Verify debug reg {} to be 0b{}. Max retries = {}".format(
            dmi_addr, expected_data, retries
        )

        # Generate vectors to start read operation from register
        vectors: List[Vector] = list(
            self.set_dmi(DMIOp.READ, dmi_addr, 32 * "0", comment=comment)
        )

        # Poll the DMIACCESS register and check the status & read register value
        condition_vectors = self.set_dmi(
            DMIOp.NOP,
            DMRegAddress.NO_REG,
            32 * "0",
            DMIResult.OP_SUCCESS,
            expected_data,
        )
        # Pad the condition vectors to be a multiple of 8
        condition_vectors = VectorBuilder.pad_vectors(
            condition_vectors, self.driver.jtag_idle_vector()
        )

        # We have to issue a reset of the DMI only to clear the busy error flag.
        idle_vectors = self.dmi_reset()
        # Pad the idle vectors to be a multiple of  8
        idle_vectors = VectorBuilder.pad_vectors(
            idle_vectors, self.driver.jtag_idle_vector()
        )

        # Create vectors for a matched loop that repeatedly polls the status register and resets the error bit on mismatch
        vectors.append(
            self.driver.vector_builder.matched_loop(
                condition_vectors, idle_vectors, retries
            )
        )
        vectors += self.driver.jtag_idle_vectors(
            8
        )  # Make sure there are at least 8 normal vectors before the next matched loop by insertion idle instructions
        return vectors

    @overload
    def write_debug_reg(
        self,
        dmi_addr: DMRegAddress,
        data: str,
        verify_completion: Literal[True] = True,
        retries: int = 1,
        comment: Optional[str] = None,
    ) -> List[Vector]:
        ...

    @overload
    def write_debug_reg(
        self,
        dmi_addr: DMRegAddress,
        data: str,
        verify_completion: Literal[False] = False,
        retries: int = 1,
        comment: Optional[str] = None,
    ) -> List[NormalVector]:
        ...

    @overload
    def write_debug_reg(
        self,
        dmi_addr: DMRegAddress,
        data: str,
        verify_completion: bool = False,
        retries: int = 1,
        comment: Optional[str] = None,
    ) -> List[Vector]:
        ...

    def write_debug_reg(
        self,
        dmi_addr: DMRegAddress,
        data: str,
        verify_completion: bool = True,
        retries: int = 1,
        comment: Optional[str] = None,
    ) -> Union[List[Vector], List[NormalVector]]:
        """
           Write to a debug register using a DMIACCESS operation.

           Notes:
              If ``verify_completion`` is True, this function uses a matched loop to verify the completion of the command
              with up to ``retries`` number of polls. Matched loops can cause lots of issues in your vector setup and you
              should avoid them at all costs. Set the ``verify_completion`` paramter to `False` to not check for command
              completion and thus not issue any matched loops.

        Args:
            dmi_addr (DMRegAddress): _description_
            data (str): _description_
            verify_completion (bool, optional): If True, use matched loops to verify command completion. Defaults to True.
            retries (int, optional): The number of polls if ``verify_completion`` is True. Ignored if verification is disabled.
            comment (Optional[str], optional): An optional comment to provide context for these vectors.

        Returns:
            Union[List[Vector], List[NormalVector]]: The list of generated vectors
        """
        if comment is None:
            comment = ""
        comment += "/Write {} to debug reg {}.".format(
            pp_binstr(BitArray(bin=data)), dmi_addr
        )
        if verify_completion:
            comment += "Max retries = {}".format(retries)

        # Generate vectors to start write operation to register
        vectors: List[Vector] = list(
            self.set_dmi(DMIOp.WRITE, dmi_addr, data, comment=comment)
        )
        # Generate a few jtag clock edges while staying in idle state
        self.driver.set_jtag_default_values()
        self.driver.vector_builder.tck = 1
        vectors += [
            self.driver.vector_builder.vector(
                repeat=5,
                comment="Clock tck for a few cycles to let dmi complete operation",
            )
        ]
        if verify_completion:
            # Check the status of the previous operation by reading the OP field of JTAG DMI Access register
            condition_vectors = self.set_dmi(
                DMIOp.NOP, DMRegAddress.NO_REG, 32 * "0", DMIResult.OP_SUCCESS
            )
            # Pad the condition vectors to be a multiple of 8
            condition_vectors = VectorBuilder.pad_vectors(
                condition_vectors, self.driver.jtag_idle_vector()
            )

            idle_vectors = self.dmi_reset()
            # Pad the idle vectors to be a multiple of  8
            idle_vectors = VectorBuilder.pad_vectors(
                idle_vectors, self.driver.jtag_idle_vector()
            )

            # Create vectors for a matched loop that repeatedly polls the status register and resets the error bit on mismatch
            vectors.append(
                self.driver.vector_builder.matched_loop(
                    condition_vectors, idle_vectors, retries
                )
            )
            vectors += self.driver.jtag_idle_vectors(
                8
            )  # Make sure there are at least 8 normal vectors before the next matched loop by insertion idle instructions
        return vectors

    def write_reg_abstract_cmd_no_loop(
        self, reg: RISCVReg, data: BitArray, comment: Optional[str] = None
    ) -> List[NormalVector]:
        """
        Write to a RISC-V core register (not a debug module register) using a debug module ABSTRACT CMD.

        This version of the command does not use any matched loops, i.e. it does not verify the completion of the command.
        You most often use this command to change the program counter of your RISC-V core to make it jump to a memory location
        you preloaded into memory.

        Args:
            reg: The RISC-V reg to modify
            data: The 32-bit data to write to the register
            comment: An optional comment to provide context.

        Returns:
            List[NormalVector]: The list of generated vectors.

        """
        if comment is None:
            comment = ""
        comment += "/Write {} to registers {}".format(pp_binstr(data), reg)

        # Write data to data0 DM reg
        vectors = self.write_debug_reg(
            DMRegAddress.DATAO, data.bin, verify_completion=False, comment=comment
        )

        # Issue the write to register command
        cmd = DMAbstractCmd(
            cmd_type=DMAbstractCmdType.ACCESS_REG,
            reg=RISCVReg.CSR_DPC,
            write=True,
            transfer=True,
            aarsize=2,
        )
        vectors += self.set_command_no_loop(cmd)
        return vectors

    def write_reg_abstract_cmd(
        self,
        reg: RISCVReg,
        data: BitArray,
        retries: int = 1,
        comment: Optional[str] = None,
    ) -> List[Vector]:
        """
        Write to a RISC-V core register (not a debug module register) using a debug module ABSTRACT CMD.

        This version of the command uses matched loops to poll for the completion of the command for up to ``retries``
        number of times. You most often use this command to change the program counter of your RISC-V core to make it
        jump to a memory location you preloaded into memory.

        Args:
            reg: The RISC-V reg to modify
            data: The 32-bit data to write to the register
            retries: The number of times to poll for command completion in the matched loop
            comment: An optional comment to provide context.

        Returns:
            List[NormalVector]: The list of generated vectors

        """

        if comment is None:
            comment = ""
        comment += "/Write {} to registers {}".format(pp_binstr(data), reg)

        # Write data to data0 DM reg
        vectors = self.write_debug_reg(
            DMRegAddress.DATAO, data.bin, retries=retries, comment=comment
        )

        # Issue the write to register command
        cmd = DMAbstractCmd(
            cmd_type=DMAbstractCmdType.ACCESS_REG,
            reg=RISCVReg.CSR_DPC,
            write=True,
            transfer=True,
            aarsize=2,
        )
        vectors += self.set_command(cmd, retries=retries)
        return vectors

    def read_reg_abstract_cmd(
        self,
        reg: RISCVReg,
        expected_data: str,
        retries: int = 1,
        comment: Optional[str] = None,
    ) -> List[Vector]:
        """
        Read from a RISC-V core register (not a debug module register) using a debug module ABSTRACT CMD.

        This version of the command uses matched loops to poll for the completion of the command for up to ``retries``
        number of times.

        Args:
            reg: The RISC-V reg to modify
            expected_data: The data to match against when reading from the register. Use the letter 'x' for don't
                care bits
            retries: The number of times to poll for command completion in the matched loop
            comment: An optional comment to provide context.

        Returns:
            List[NormalVector]: The list of generated vectors

        """
        if comment is None:
            comment = ""
        comment += "Verify register {} equals {}".format(reg, expected_data)

        # Issue the read from register command
        cmd = DMAbstractCmd(
            cmd_type=DMAbstractCmdType.ACCESS_REG,
            reg=RISCVReg.CSR_DPC,
            write=False,
            transfer=True,
            aarsize=2,
        )
        vectors = self.set_command(cmd, retries=retries)

        # Read data from data0 DM reg
        vectors += self.read_debug_reg(
            DMRegAddress.DATAO, expected_data, retries=retries, comment=comment
        )
        return vectors

    def read_reg_abstract_cmd_no_loop(
        self,
        reg: RISCVReg,
        expected_data: str,
        wait_cycles: int = 10,
        comment: Optional[str] = None,
    ) -> List[NormalVector]:
        """
        Read from a RISC-V core register (not a debug module register) using a debug module ABSTRACT CMD.

        This version of the command does not use any matched loops, i.e. it does not verify the completion of the command.

        Args:
            reg: The RISC-V reg to modify
            expected_data: The data to match against when reading from the register. Use the letter 'x' for don't
                care bits
            comment: An optional comment to provide context.

        Returns:
            List[NormalVector]: The list of generated vectors.

        """

        if comment is None:
            comment = ""
        comment += "Verify register {} equals {}".format(reg, expected_data)

        # Issue the read from register command
        cmd = DMAbstractCmd(
            cmd_type=DMAbstractCmdType.ACCESS_REG,
            reg=RISCVReg.CSR_DPC,
            write=False,
            transfer=True,
            aarsize=2,
        )
        vectors = self.set_command_no_loop(cmd, wait_cycles=wait_cycles)

        # Read data from data0 DM reg
        vectors += self.read_debug_reg_no_loop(
            DMRegAddress.DATAO, expected_data, wait_cycles=wait_cycles, comment=comment
        )
        return vectors

    def halt_hart(
        self, hartsel: BitArray, comment: Optional[str] = None, retries: int = 1
    ) -> List[Vector]:
        """
        Halts the RISC-V hart (core).

        This command makes the debug module assert the debug request line of the selected Hart (RISC-V debug spec
        terminology for a core) which will cause the core to jump to the debug memory location (which contains an
        infinite loop to trap the core).

        This version of the function uses matched loops to poll until (up to ``retries`` number of times) the selected
        hart jumped to the debug memory location and is thus "halted".
        Args:
            hartsel: The hartid of the core to halt.
            comment: An optional comment for context
            retries: The maximum number of times the matched loop should poll the 'allhalted' status bit.

        Returns:
            The list of generated vectors.

        """
        if comment is None:
            comment = ""
        comment += "/Halting hart {}".format(pp_binstr(hartsel))
        new_dm_value: BitArray = BitArray(32)  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
        new_dm_value[31] = 1  # haltreq
        new_dm_value[16:26] = hartsel[0:10]  # hartsello
        new_dm_value[6:16] = hartsel[10:20]  # hartselhi
        new_dm_value[
            0
        ] = 1  # Dmactive, if we were to write a zero we would reset the dmi
        vectors = self.write_debug_reg(
            DMRegAddress.DMCONTROL, new_dm_value.bin, retries=1, comment=comment
        )

        # Poll the DMSTATUS reg
        expected_dm_status: BitArray = BitArray(32)  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
        mask: BitArray = BitArray(32)  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
        expected_dm_status[9] = 1  # 1 #All halted
        mask[9] = 1
        expected_dm_status_value = ""
        # Iterate over bits LSB-first
        for bit, maskbit in zip(expected_dm_status, mask):  # type: ignore
            if maskbit:
                expected_dm_status_value += str(int(bit))
            else:
                expected_dm_status_value += "X"
        # Reverse the order since read_debug_reg expects data in MSB-to-LSB order
        expected_dm_status_value = expected_dm_status_value[::-1]
        vectors += self.read_debug_reg(
            DMRegAddress.DMSTATUS,
            expected_dm_status_value,
            retries,
            comment="Poll until allhalted flag is set",
        )

        # Clear halreq bit
        new_dm_value[31] = 0
        vectors += self.write_debug_reg(
            DMRegAddress.DMCONTROL,
            new_dm_value.bin,
            verify_completion=False,
            comment=comment,
        )
        return vectors

    def halt_hart_no_loop(
        self, hartsel: BitArray, comment: Optional[str] = None, wait_cycles: int = 10
    ) -> List[NormalVector]:
        """
        Halts the RISC-V hart (core).

        This command makes the debug module assert the debug request line of the selected Hart (RISC-V debug spec
        terminology for a core) which will cause the core to jump to the debug memory location (which contains an
        infinite loop to trap the core).

        This version of the function does not use matched loops but instead wait for the specified number of JTAG idle
        cycles for the core to halt before matching the allhalted status flag. You should try to increase this value if
        your core is slow to halt.

        Args:
            hartsel: The hartid of the core to halt.
            comment: An optional comment for context
            wait_cycles: The maximum number of times the matched loop should poll the 'allhalted' status bit.

        Returns:
            The list of generated vectors.

        """

        if comment is None:
            comment = ""
        comment += "/Halting hart {}".format(pp_binstr(hartsel))
        new_dm_value: BitArray = BitArray(32)  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
        new_dm_value[31] = 1  # haltreq
        new_dm_value[16:26] = hartsel[0:10]  # hartsello
        new_dm_value[6:16] = hartsel[10:20]  # hartselhi
        new_dm_value[
            0
        ] = 1  # Dmactive, if we were to write a zero we would reset the dmi
        vectors = self.write_debug_reg(
            DMRegAddress.DMCONTROL,
            new_dm_value.bin,
            verify_completion=False,
            comment=comment,
        )

        # Check the DMSTATUS reg after wait cycles
        vectors += [
            self.driver.jtag_idle_vector(
                repeat=wait_cycles, comment="Waiting for core to halt"
            )
        ]
        # breakpoint()
        expected_dm_status: BitArray = BitArray(32)  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
        mask: BitArray = BitArray(32)  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
        expected_dm_status[9] = 1  # 1 #All halted
        mask[9] = 1
        expected_dm_status_value = ""
        # Iterate over bits LSB-first
        for bit, maskbit in zip(expected_dm_status, mask):  # type: ignore
            if maskbit:
                expected_dm_status_value += str(int(bit))
            else:
                expected_dm_status_value += "X"
        # Reverse the order since read_debug_reg expects data in MSB-to-LSB order
        expected_dm_status_value = expected_dm_status_value[::-1]
        vectors += self.read_debug_reg_no_loop(
            DMRegAddress.DMSTATUS,
            expected_dm_status_value,
            wait_cycles=wait_cycles,
            comment="Check if allhalted flag is set",
        )

        # Clear halreq bit
        new_dm_value[31] = 0
        vectors += self.write_debug_reg(
            DMRegAddress.DMCONTROL,
            new_dm_value.bin,
            verify_completion=False,
            comment=comment,
        )
        return vectors

    def resume_harts(
        self, hartsel: BitArray, comment: Optional[str] = None, retries: int = 1
    ) -> List[Vector]:
        """
        Resume the RISC-V hart (core).

        This command will cause the debug module to resume normal execution on the selected hart.

        This version of the function uses matched loops to poll until (up to ``retries`` number of times) the selected
        hart resumed regular operation and the `allresumeack` flag in the DMSTATUS reg is set.

        Args:
            hartsel: The hartid of the core to halt.
            comment: An optional comment for context
            retries: The maximum number of times the matched loop should poll the 'allhalted' status bit.

        Returns:
            The list of generated vectors.

        """

        if comment is None:
            comment = ""
        comment += "/Resume hart {}".format(pp_binstr(hartsel))

        new_dm_value: BitArray = BitArray(32)  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
        new_dm_value[30] = 1  # resumereq
        new_dm_value[16:26] = hartsel[0:10]  # hartsello
        new_dm_value[6:16] = hartsel[10:20]  # hartselhi
        new_dm_value[
            0
        ] = 1  # Dmactive, if we were to write a zero we would reset the dmi
        vectors = self.write_debug_reg(
            DMRegAddress.DMCONTROL, new_dm_value.bin, retries=1, comment=comment
        )

        # Poll the DMSTATUS reg
        expected_dm_status: BitArray = BitArray(32)  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
        mask: BitArray = BitArray(32)  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
        expected_dm_status[17] = 1  # allresumeack
        mask[17] = 1
        mask[23:32] = 1
        expected_dm_status_value = ""
        # Iterate over bits LSB-first
        for bit, maskbit in zip(expected_dm_status, mask):  # type: ignore
            if maskbit:
                expected_dm_status_value += str(int(bit))
            else:
                expected_dm_status_value += "X"
        # Reverse the order since read_debug_reg expects data in MSB-to-LSB order
        expected_dm_status_value = expected_dm_status_value[::-1]
        vectors += self.read_debug_reg(
            DMRegAddress.DMSTATUS,
            expected_dm_status_value,
            retries,
            comment="Poll until allresumeack flag is set",
        )

        # Clear resumereq bit
        new_dm_value[30] = 0
        vectors += self.write_debug_reg(
            DMRegAddress.DMCONTROL,
            new_dm_value.bin,
            verify_completion=False,
            comment=comment,
        )
        return vectors

    def resume_harts_no_loop(
        self, hartsel: BitArray, comment: Optional[str] = None, wait_cycles: int = 10
    ) -> List[NormalVector]:
        """
        Resume the RISC-V hart (core).

        This command will cause the debug module to resume normal execution on the selected hart.

        This version of the function does not use matched loops but instead waits for the specified number of JTAG idle
        cycles for the cores to resume before matching the `allresumeack` status flag. You should try to increase this
        value if your core is slow to resume.

        Args:
            hartsel: The hartid of the core to halt.
            comment: An optional comment for context
            wait_cycles: The maximum number of times the matched loop should poll the 'allhalted' status bit.

        Returns:
            The list of generated vectors.

        """
        if comment is None:
            comment = ""
        comment += "/Resume hart {}".format(hartsel)

        new_dm_value: BitArray = BitArray(32)  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
        new_dm_value[30] = 1  # resumereq
        new_dm_value[16:26] = hartsel[0:10]  # hartsello
        new_dm_value[6:16] = hartsel[10:20]  # hartselhi
        new_dm_value[
            0
        ] = 1  # Dmactive, if we were to write a zero we would reset the dmi
        vectors = self.write_debug_reg(
            DMRegAddress.DMCONTROL,
            new_dm_value.bin,
            verify_completion=False,
            comment=comment,
        )

        # Check the DMSTATUS reg after wait cycles
        vectors += [
            self.driver.jtag_idle_vector(
                repeat=wait_cycles,
                comment="Waiting for {} cycles before checking if core halted.".format(
                    wait_cycles
                ),
            )
        ]
        expected_dm_status: BitArray = BitArray(32)  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
        mask: BitArray = BitArray(32)  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
        expected_dm_status[17] = 1  # allresumeack
        mask[17] = 1
        mask[23:32] = 1
        expected_dm_status_value = ""
        # Iterate over bits LSB-first
        for bit, maskbit in zip(expected_dm_status, mask):  # type: ignore
            if maskbit:
                expected_dm_status_value += str(int(bit))
            else:
                expected_dm_status_value += "X"
        # Reverse the order since read_debug_reg expects data in MSB-to-LSB order
        expected_dm_status_value = expected_dm_status_value[::-1]
        vectors += self.read_debug_reg_no_loop(
            DMRegAddress.DMSTATUS,
            expected_dm_status_value,
            wait_cycles=wait_cycles,
            comment="Check if allresumeack flag is set",
        )

        # Clear resumereq bit
        new_dm_value[30] = 0
        vectors += self.write_debug_reg(
            DMRegAddress.DMCONTROL,
            new_dm_value.bin,
            verify_completion=False,
            comment=comment,
        )
        return vectors

    @overload
    def writeMem(
            self,
            addr: BitArray,
            data: BitArray,
            verify_completion: Literal[True] = True,
            retries: int = 1,
            comment: Optional[str] = None,
    ) -> List[Vector]:
        ...
    @overload
    def writeMem(
            self,
            addr: BitArray,
            data: BitArray,
            verify_completion: Literal[False] = True,
            retries: int = 1,
            comment: Optional[str] = None,
    ) -> List[NormalVector]:
        ...

    @overload
    def writeMem(
        self,
        addr: BitArray,
        data: BitArray,
        verify_completion: bool = True,
        retries: int = 1,
        comment: Optional[str] = None,
    ) -> List[Vector]:
        ...

    def writeMem(
        self,
        addr: BitArray,
        data: BitArray,
        verify_completion: bool = True,
        retries: int = 1,
        comment: Optional[str] = None,
    ) -> Union[List[Vector], List[NormalVector]]:
        """
       Write to a single 32-bit memory location using the "system bus access" (SBA) feature of the debug module.

       Notes:
              If ``verify_completion`` is True, this function uses a matched loop to verify the completion of the command
              with up to ``retries`` number of polls. Matched loops can cause lots of issues in your vector setup and you
              should avoid them at all costs. Set the ``verify_completion`` paramter to `False` to not check for command
              completion and thus not issue any matched loops.

       Args:
           addr: The address to read from
           data: The 32-bit data to write to the memory location.
           retries: The number of times to poll the DTMCSR register for the operation to complete.
           comment: An optional comment to provide context for these vectors.

       Returns:

       """
        if comment is None:
            comment = ""
        comment += "/Writing {} to memory @{}".format(pp_binstr(data), pp_binstr(addr))
        vectors = self.write_debug_reg(
            DMRegAddress.SBADDRESS0,
            addr.bin,
            verify_completion=verify_completion,
            retries=retries,
            comment=comment,
        )
        vectors += self.write_debug_reg(
            DMRegAddress.SBDATA0,
            data.bin,
            verify_completion=verify_completion,
            retries=retries,
            comment=comment,
        )
        return vectors

    def readMem(
        self,
        addr: BitArray,
        expected_data: Union[str, BitArray],
        retries: int = 1,
        comment: Optional[str] = None,
    ) -> List[Vector]:
        """
        Read from a single 32-bit memory location using the "system bus access" (SBA) feature of the debug module.

        Notes:
            This version of the command uses matched loops to poll for command completion with up to `retries` number of
            tries before failling. Since Matched loops can cause lots of issues in your vector setup, you should avoid them
            at all costs. Use the `_no_loop` version of this command instead to wait for a fixed number of idle cycles instead.

        Args:
            addr: The address to read from
            expected_data: The 32-bit data to match against the read data. Use the letter 'x' for don't care bits.
            retries: The number of times to poll the DTMCSR register for the operation to complete before matching against
                the read-back data.
            comment: An optional comment to provide context for these vectors.

        Returns:

        """
        if isinstance(expected_data, BitArray):
            expected_data = expected_data.bin
            expected_data_repr = pp_binstr(expected_data)
        else:
            if re.fullmatch(r"[01]+", expected_data):
                expected_data_repr = pp_binstr(BitArray(expected_data))
            else:
                expected_data_repr = expected_data

        assert isinstance(expected_data, str)  # Fix type check errors
        if comment is None:
            comment = ""
        comment += "/Reading from systembus @{} expecting {}".format(
            pp_binstr(addr), expected_data_repr
        )
        vectors = self.write_debug_reg(
            DMRegAddress.SBADDRESS0, addr.bin, retries=retries, comment=comment
        )
        vectors += self.read_debug_reg(
            DMRegAddress.SBDATA0, expected_data, retries=retries
        )
        return vectors

    def readMem_no_loop(
        self,
        addr: BitArray,
        expected_data: Union[str, BitArray],
        wait_cycles: int,
        comment: Optional[str] = None,
    ) -> List[NormalVector]:
        """
        Read from a single 32-bit memory location using the "system bus access" (SBA) feature of the debug module.

        This version of the command does not use matched loops but wait for a configurable number of JTAG idle cycles.

        Notes:
            You have to enable the readonaddr flag of the debug module before issuing readMem commands.

        Args:
            addr: The address to read from
            expected_data: The 32-bit data to match against the read data. Use the letter 'x' for don't care bits.
            wait_cycles: The number of JTAG Idle cycles to wait for the read operation to complete
            comment: An optional comment to provide context for these vectors

        Returns:
            The list of generated vectors
        """
        if isinstance(expected_data, BitArray):
            expected_data = expected_data.bin
            expected_data_repr = pp_binstr(expected_data)
        else:
            if re.fullmatch(r"[01]+", expected_data):
                expected_data_repr = pp_binstr(BitArray(expected_data))
            else:
                expected_data_repr = expected_data

        assert isinstance(expected_data, str)  # Fix type check errors
        if comment is None:
            comment = ""
        comment += "/Reading from systembus @0x{} expecting 0x".format(
            addr.hex, expected_data_repr
        )
        vectors = self.write_debug_reg(
            DMRegAddress.SBADDRESS0, addr.bin, verify_completion=False, comment=comment
        )
        vectors += [
            self.driver.jtag_idle_vector(
                repeat=wait_cycles,
                comment="Wait for a few cylces to let the bus transaction complete",
            )
        ]
        vectors += self.read_debug_reg_no_loop(
            DMRegAddress.SBDATA0, expected_data, wait_cycles=wait_cycles
        )
        return vectors

    def enable_sbreadonaddr(self) -> List[NormalVector]:
        """
        Enable auto read on systembus
        Returns:

        """
        # Enable sbreadonaddr by writing appropriate values to SBCS register
        sbcs_value: BitArray = BitArray(32)  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
        sbcs_value[29:32] = 1
        sbcs_value[20] = 1
        sbcs_value[17:20] = 2
        return self.write_debug_reg(
            DMRegAddress.SBCS,
            sbcs_value.bin,
            verify_completion=False,
            comment="Enable sbreadonaddr flag in SBCS reg for " "subsequent reads.",
        )

    def check_end_of_computation(
        self,
        expected_return_code: int,
        wait_cycles: int = 10,
        eoc_reg_addr: str = "0x1a1040a0",
    ) -> List[Vector]:
        vectors: List[Vector] = list(self.enable_sbreadonaddr())

        expected_eoc_value: BitArray = BitArray(int=expected_return_code, length=32)  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
        expected_eoc_value[31] = 1
        vectors += self.readMem_no_loop(
            BitArray(eoc_reg_addr),  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
            expected_eoc_value,
            wait_cycles=wait_cycles,
            comment="Check for end of computation with expected return code {}".format(
                expected_return_code
            ),
        )
        return vectors

    def wait_for_end_of_computation(
        self,
        expected_return_code: int,
        idle_vector_count: int = 10,
        max_retries: int = 10,
        eoc_reg_addr: str = "0x1a1040a0",
    ) -> List[Vector]:
        vectors: List[Vector] = list(self.enable_sbreadonaddr())

        expected_eoc_value: BitArray = BitArray(int=expected_return_code, length=32)  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
        expected_eoc_value[31] = 1
        condition_vectors = self.readMem_no_loop(
            BitArray(eoc_reg_addr),  # type: ignore until https://github.com/scott-griffiths/bitstring/issues/276 is closed
            expected_eoc_value,
            comment="Wait for end of computation with expected return code {}".format(
                expected_return_code
            ),
        )
        # Pad the condition vectors to be a multiple of 8
        condition_vectors = VectorBuilder.pad_vectors(
            condition_vectors, self.driver.jtag_idle_vector()
        )

        idle_vectors = self.driver.jtag_idle_vectors(count=idle_vector_count)
        idle_vectors = VectorBuilder.pad_vectors(
            idle_vectors, self.driver.jtag_idle_vector()
        )
        vectors.append(
            self.driver.vector_builder.matched_loop(
                condition_vectors, idle_vectors, max_retries
            )
        )
        vectors += self.driver.jtag_idle_vectors(
            8
        )  # Make sure there are at least 8 normal vectors before the next matched loop by insertion idle instructions
        return vectors
