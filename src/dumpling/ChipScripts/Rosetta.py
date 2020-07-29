import contextlib
import re
from pathlib import Path

import click
from dumpling.Common.ElfParser import ElfParser
from bitstring import BitArray
from dumpling.Common.HP93000 import HP93000VectorWriter
from dumpling.Common.PulpJTAGTapRosetta import PULPJTagTapRosetta
from dumpling.Common.VectorBuilder import VectorBuilder
from dumpling.Drivers.JTAG import JTAGDriver
from dumpling.JTAGTaps.RISCVDebugTap import RISCVDebugTap, RISCVReg



pins = {
        'chip_reset' : {'name': 'pad_reset_n', 'default': '0'},
        'trst': {'name': 'pad_jtag_trst', 'default': '1'},
        'tms': {'name': 'pad_jtag_tms', 'default': '0'},
        'tck': {'name': 'pad_jtag_tck', 'default': '0'},
        'tdi': {'name': 'pad_jtag_tdi', 'default': '0'},
        'tdo': {'name': 'pad_jtag_tdo', 'default': 'X'}
    }
FC_CORE_ID = BitArray('0x003e0')

vector_builder = VectorBuilder(pins)
jtag_driver = JTAGDriver(vector_builder)

# Instantiate the two JTAG taps in Rosetta
riscv_debug_tap = RISCVDebugTap(jtag_driver)
pulp_tap = PULPJTagTapRosetta(jtag_driver)
# Add the taps to the jtag chain in the right order
jtag_driver.add_tap(riscv_debug_tap)
jtag_driver.add_tap(pulp_tap)


#Commands
pass_VectorWriter = click.make_pass_decorator(HP93000VectorWriter)


#Entry point for all rosetta related commands
@click.group()
@click.option("--port-name", '-p', type=str, default="jtag_and_reset_port", show_default=True)
@click.option("--wtb-name", '-w', type=str, default="multiport_ext_clk_wvtbl", show_default=True)
@click.option('--output', '-o', type=click.Path(exists=False, file_okay=True, writable=True), required=True)
@click.option("--device_cycle_name", '-d', type=str, default="dvc_1", )
@click.pass_context
def rosetta(ctx, port_name, wtb_name, device_cycle_name, output):
    """Generate stimuli for the TSMC65 Rosetta chip.
    """
    #Instantiate the vector writer and attach it to the command context so subcommands can access it.
    ctx.obj = HP93000VectorWriter(stimuli_file_path=Path(output), pins=pins, port=port_name, device_cycle_name=device_cycle_name, wtb_name=wtb_name)



@rosetta.command()
@click.option("--blade/--no-blade", default=True, help="Enables/Disables the BLADE SRAM macros in Rosetta", show_default=True)
@click.option("--edram/--no-edram", default=True, help="Enables/Disables the eDRAM macros in Rosetta", show_default=True)
@click.option("--hd-mem-backend", type=click.Choice('edram', 'scm'), default='scm', show_default=True,
              help="Switches between SCM and eDRAM as the memory backend for the HD-Computing Accelerator")
@click.option("--bypass-soc-fll", is_flag=True, default=True, help="Bypass the FLL for the SoC clock and use the external SoC clock instead.")
@click.option("--bypass-per-fll", is_flag=True, default=True, help="Bypass the FLL for the Peripheral clock and use the external clock instead.")
@pass_VectorWriter
def write_soc_config(vector_writer: HP93000VectorWriter, elf, return_code, wait_cycles, verify, blade, edram, hd_mem_backend, bypass_soc_fll, bypass_per_fll):
    """
    Writes the given static configuration value to the apb_soc_ctrl register

    """
    with vector_writer as writer:
        # Set the config register to bypass the internall FLLs and release hardreset
        vectors = pulp_tap.init_pulp_tap()
        vectors += pulp_tap.set_config_reg(BitArray(8), soc_fll_bypass_en=bypass_soc_fll, per_fll_bypass_en=bypass_per_fll, blade_disable=not blade, edram_disable=not edram,
                                          hd_mem_backend_use_edram=hd_mem_backend == 'edram')
        writer.write_vectors(vectors)


@rosetta.command()
@click.option("--elf", "-e", required=True, type=click.Path(exists=True, file_okay=True, dir_okay=False), help="The path to the elf binary to preload.")
@click.option("--return-code", '-r', type=click.IntRange(min=0, max=255), help="Set a return code to check against during end of computation detection. A matched loop will be inserted to achieve ")
@click.option("--eoc-wait-cycles", '-w', default=0, type=click.IntRange(min=0), help="If set to a non zero integer, wait the given number of cycles for end of computation check and bdon't use ")
@click.option("--verify/--no-verify", default=True, help="Enables/Disables verifying the content written to L2.", show_default=True)
@click.option("--blade/--no-blade", default=True, help="Enables/Disables the BLADE SRAM macros in Rosetta", show_default=True)
@click.option("--edram/--no-edram", default=True, help="Enables/Disables the eDRAM macros in Rosetta", show_default=True)
@click.option("--hd-mem-backend", type=click.Choice(['edram', 'scm']), default='scm', show_default=True, help="Switches between SCM and eDRAM as the memory backend for the HD-Computing "
                                                                                                                 "Accelerator")
@click.option("--bypass-soc-fll", is_flag=True, default=True, help="Bypass the FLL for the SoC clock and use the external SoC clock instead.")
@click.option("--bypass-per-fll", is_flag=True, default=True, help="Bypass the FLL for the Peripheral clock and use the external clock instead.")
@click.option("--compress", '-c', is_flag=True, default=False, show_default=True, help="Compress all vectors by merging subsequent identical vectors into a single vector with increased repeat value.")
@pass_VectorWriter
def execute_elf(writer: HP93000VectorWriter, elf, return_code, eoc_wait_cycles, verify, blade, edram, hd_mem_backend, bypass_soc_fll, bypass_per_fll, compress):
    """Generate vectors to load and execute the given elf binary.

    The command parses the binary supplied with the '--elf' parameter and
    writes the generated stimuli to the given OUTPUT file. Additionally to the
    AVC ASCII output, a .wtb and .tmf with identical basename is created. The
    vectors take care of resetting the chip, halting the core, preloading the
    binary into L2 memory with optional verification and resuming the core. If
    an expected return code is supplied with the optional '--return-code' flag,
    either a matched loop (polling) check or a single check (after a
    configurable number of idle clock cycles) for end of computation is added
    to the end of the stimuli vectors depending on the value of
    --eoc-wait-cycles.

    """

    with writer as vector_writer:
        vectors = []
        # Assert reset
        vector_builder.chip_reset = 0
        # Wait 1us
        reset_vector = vector_builder.vector(comment="Assert reset")
        vectors += vector_builder.loop([reset_vector], 10)
        # Write the vectors to disk
        vector_writer.write_vectors(vectors, compress=compress)

        # Reset the jtag interface and wait for 10 cycles
        vectors = jtag_driver.jtag_reset()
        vectors += jtag_driver.jtag_idle_vectors(10)
        vector_writer.write_vectors(vectors, compress=compress)

        # Set the config register to bypass the internall FLLs and release hardreset
        vectors = pulp_tap.set_config_reg(BitArray(8), soc_fll_bypass_en=bypass_soc_fll, per_fll_bypass_en=bypass_per_fll, blade_disable=not blade, edram_disable=not edram,
                                          hd_mem_backend_use_edram=hd_mem_backend=='edram')
        vectors += jtag_driver.jtag_idle_vectors(10)
        vector_builder.chip_reset = 1
        vectors += [vector_builder.vector(comment="Release hard reset")]
        vector_writer.write_vectors(vectors, compress=compress)

        # Try writing to L2 memory with PULP Tap
        vectors = pulp_tap.init_pulp_tap()
        vectors += pulp_tap.write32(BitArray('0x1c008080'), [BitArray('0xabbaabba')], comment="Write testpattern 0xABBAABBA to L2 start")
        vectors += pulp_tap.read32_no_loop(BitArray('0x1c008080'), [BitArray('0xabbaabba')], comment="Verify testpattern. Expecting to read 0xABBAABBA")
        vector_writer.write_vectors(vectors, compress=compress)

        # Start boot procedure
        # Halt fabric controller
        vectors = riscv_debug_tap.init_dmi()
        vectors += riscv_debug_tap.set_dmactive(True)
        vectors += riscv_debug_tap.halt_hart_no_loop(FC_CORE_ID, wait_cycles=50)

        vector_writer.write_vectors(vectors, compress=compress)

        # Write the boot address into dpc
        parser = ElfParser()
        parser.add_binary(elf)
        entry_address = BitArray(int=parser.get_entry(), length=32)
        vectors = riscv_debug_tap.write_reg_abstract_cmd_no_loop(RISCVReg.CSR_DPC, BitArray(entry_address), comment="Writing boot address to DPC")
        vector_writer.write_vectors(vectors, compress=compress)

        # Verify boot address
        vectors = riscv_debug_tap.read_reg_abstract_cmd_no_loop(RISCVReg.CSR_DPC, BitArray(entry_address).bin, wait_cycles=10, comment="Reading DPC")
        vector_writer.write_vectors(vectors, compress=compress)

        # Load L2 memory
        vectors = pulp_tap.init_pulp_tap()
        vectors += pulp_tap.loadL2(elf_binary=elf)
        vector_writer.write_vectors(vectors, compress=compress)

        # Optionally verify the data we just wrote to L2
        if verify:
            vectors = pulp_tap.verifyL2_no_loop(elf, comment="Verify the content of L2 to match the binary.")
            vector_writer.write_vectors(vectors)

        # Resume core
        vectors = riscv_debug_tap.init_dmi()  # Change JTAG IR to DMIACCESS
        vectors += riscv_debug_tap.resume_harts_no_loop(FC_CORE_ID, wait_cycles=50)
        vector_writer.write_vectors(vectors, compress=compress)

        # Wait for end of computation by polling EOC register address
        if return_code != None:
            if eoc_wait_cycles <= 0:
                vectors = riscv_debug_tap.wait_for_end_of_computation(0, idle_vector_count=100, max_retries=10)
            else:
                vectors = [jtag_driver.jtag_idle_vector(repeat=1000, comment="Waiting for computation to finish before checking EOC register.")]
                vectors += riscv_debug_tap.check_end_of_computation(0, wait_cycles=10)
            vector_writer.write_vectors(vectors, compress=compress)



@rosetta.command()
@click.argument('address_value_mappings', nargs=-1)
@click.option("--verify/--no-verify", default=True, help="Enables/Disables verifying the content written to L2.", show_default=True)
@click.option("--loop/--no-loop", default=False, help="If true, all matched loops  in the verification vectors are replaced with reasonable delays to avoid the usage of matched loops altogether.")
@pass_VectorWriter
def write_mem(vector_writer: HP93000VectorWriter, address_value_mappings, verify, loop):
    """
    Perform write transactions to the system bus.

    Each value of ADDRESS_VALUE_MAPPING should be of the kind 'address=value[#Comment]' where
    address and value are 32-bit value in hex notation and comment is an optional comment to attach to the vectors.
    E.g.::

    write_mem "0x1c008080=0xdeafbeef#Write to start address" 0x1c008084=0x12345678

    If the optional verify flag is provided, the data written will be read back for verification.
    """
    #Parse all address value mappings and store the result in a list of tuples
    data = []
    pattern = re.compile(r"(?P<address>0x[0-9a-f]{8})=(?P<value>0x[0-9a-f]{0,8})(?:#(?P<comment>.*))?")
    for mapping in address_value_mappings:
        match = pattern.match(mapping)
        if not match:
            raise click.BadArgumentUsage("Illegal argument: {}. Must be of the form 0x<32-bit address>=0x<value>#comment".format(mapping))
        else:
            data.append((BitArray(match.group('address')), BitArray(match.group('value')), match.group('comment')))

    with vector_writer as writer:
        vectors = pulp_tap.init_pulp_tap()
        for address, value, comment in data:
            vectors += pulp_tap.write32(start_addr=address, data=[value], comment=comment if comment else "")
            writer.write_vectors(vectors, compress=True)
        if verify:
            for address, value, comment in data:
                if loop:
                    vectors = pulp_tap.read32(start_addr=address, expected_data=[value], comment=comment)
                else:
                    vectors = pulp_tap.read32_no_loop(start_addr=address, expected_data=[value], comment=comment if comment else "")
                writer.write_vectors(vectors, vectors)


@rosetta.command()
@click.argument('address_value_mappings', nargs=-1)
@click.option("--loop/--no-loop", default=False, help="If true, all matched loops in the verification vectors are replaced with reasonable delays to avoid the usage of matched loops altogether.")
@pass_VectorWriter
def verify_mem(vector_writer: HP93000VectorWriter, address_value_mappings, loop):
    """
    Perform read transactions on the system bus and compare the values with expected ones

    Each value of ADDRESS_VALUE_MAPPING should be of the kind 'address=value[#Comment]' where
    address and value are 32-bit value in hex notation and comment is an optional comment to attach to the vectors.
    E.g.::

    write_mem "0x1c008080=0xdeafbeef#Write to start address" 0x1c008084=0x12345678

    """
    #Parse all address value mappings and store the result in a list of tuples
    data = []
    pattern = re.compile(r"(?P<address>0x[0-9a-f]{8})=(?P<value>0x[0-9a-f]{0,8})(?:#(?P<comment>.*))?")
    for mapping in address_value_mappings:
        match = pattern.match(mapping)
        if not match:
            raise click.BadArgumentUsage("Illegal argument: {}. Must be of the form 0x<32-bit address>=0x<value>#comment".format(mapping))
        else:
            data.append((BitArray(match.group('address')), BitArray(match.group('value')), match.group('comment')))

    with vector_writer as writer:
        vectors = pulp_tap.init_pulp_tap()
        for address, value, comment in data:
            if loop:
                vectors += pulp_tap.read32(start_addr=address, expected_data=[value], comment=comment)
            else:
                vectors += pulp_tap.read32_no_loop(start_addr=address, expected_data=[value], comment=comment if comment else "")
            writer.write_vectors(vectors, vectors)

@rosetta.command()
@click.argument('expected_pc', type=str)
@click.option('--resume/--no-resume', show_default=True, default=False, help="Resume the core after reading the program counter.")
@pass_VectorWriter
def halt_core_verify_pc(vector_writer: HP93000VectorWriter, expected_pc, resume):
    """Halt the core, read the program counter comparing it with EXPECTED_PC and resume the core.

    This command is mainly useful to verify or debug the execution state of a program. The generated vectors will halt the core,
    read the programm counter and (optionally) resume the core.
    """
    with vector_writer as writer:
        vectors = riscv_debug_tap.init_dmi()
        vectors += riscv_debug_tap.halt_hart_no_loop(FC_CORE_ID, wait_cycles=100)
        expected_pc = BitArray(expected_pc)
        expected_pc = (32-len(expected_pc)) + expected_pc #Extend to 32-bit
        vectors += riscv_debug_tap.read_reg_abstract_cmd_no_loop(RISCVReg.CSR_DPC, BitArray(expected_pc,length=32).bin, wait_cycles=100, comment="Reading DPC")
        if resume:
            vectors += riscv_debug_tap.resume_harts_no_loop(FC_CORE_ID, comment="Resuming the core", wait_cycles=100)
        writer.write_vectors(vectors)

