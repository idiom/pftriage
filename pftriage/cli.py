# -*- coding: utf-8 -*-
import click
from pftriage import PFTriage, AnalysisResult
import pefile
import hashlib

# Enable -h switch for help
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

@click.group(context_settings=CONTEXT_SETTINGS)
def cli():
    pass

@cli.command(context_settings=CONTEXT_SETTINGS)
@click.argument("target")
def metadata(target):
    """Display file metadata"""
    target = PFTriage(target)
    click.echo('[*] Processing File details...')
    click.echo('Hashes')
    for hash in target.hashes:
        click.echo('{:4}{:<16} {}'.format('', hash, target.hashes[hash]))

    click.echo('File Details')
    for key in target.metadata:
        click.echo('{:4}{:<16} {}'.format('',key, target.metadata[key]))

    flags = target.get_image_flags()
    click.echo('{:4}{:<16}'.format('', "Characteristics"))
    for flag in flags:
        click.echo('{:20s} {:<20s}'.format('', flag))

    print_versioninfo(target.getstringentries())


def print_versioninfo(versioninfo):

    # output the version info blocks.
    click.echo('')
    click.echo('{:4}{:<16}'.format('', 'Version Info'))
    if 'StringInfo' in versioninfo:
        sinfo = versioninfo['StringInfo']
        if len(sinfo) == 0:
            click.echo('{:4} {}'.format('', 'No version info block...'))
        else:
            for str_entry in sinfo:
                click.echo('{:4}{:<16} {}'.format('', str_entry, sinfo[str_entry].encode('utf-8')))

    click.echo('')
    click.echo('{:4}{:<16}'.format('', 'Language Info'))
    if 'VarInfo' in versioninfo:
        vinfo = versioninfo['VarInfo']
        if len(vinfo) == 0:
            click.echo('{:4} {}'.format('', 'No language info block...'))
        else:
            print ''
            for str_entry in vinfo:
                if str_entry == 'LangID':
                    try:
                        click.echo('{:4}{:<16} {} ({})'.format('', 'LangID', PFTriage.langID[int(vinfo[str_entry], 16)], vinfo[str_entry].encode('utf-8')))
                    except KeyError:
                        click.echo('{:4}{:<16} {} ({})'.format('', 'LangID', 'Invalid Identifier!', vinfo[str_entry].encode('utf-8')))
                elif str_entry == 'charsetID':
                    try:
                        click.echo('{:4}{:<16} {} ({})'.format('', 'charsetID', PFTriage.charsetID[int(vinfo[str_entry])], vinfo[str_entry].encode('utf-8')))
                    except KeyError:
                        click.echo('{:4}{:<16} {} ({})'.format('', 'charsetID', 'Error Invalid Identifier!', vinfo[str_entry].encode('utf-8')))
                else:
                    click.echo('{:4}{:<16} {}'.format('', str_entry, vinfo[str_entry].encode('utf-8')))
    click.echo('')

@cli.command(context_settings=CONTEXT_SETTINGS)
@click.argument("target")
def imports(target):
    """Display library imports"""
    target = PFTriage(target)
    modules = target.listimports()
    print " ---- Imports ----  "
    print ' Number of imported modules: %s \n ' % len(modules)
    for str_entry in modules:
        print '\n %s ' % str_entry
        for symbol in modules[str_entry]:
            if symbol.import_by_ordinal is True:
                if symbol.name is not None:
                    print '  |-- %s Ordinal[%s] (Imported by Ordinal)' % (symbol.name, str(symbol.ordinal))
                else:
                    print '  |-- Ordinal[%s] (Imported by Ordinal)' % (str(symbol.ordinal))
            else:
                print '  |-- %s' % symbol.name
    print '\n\n'


@cli.command(context_settings=CONTEXT_SETTINGS)
@click.argument("target")
@click.option("-v", "--verbose", is_flag=True, help="Display detailed section information")
def sections(target, verbose):
    """Display section information about the file"""
    target = PFTriage(target)
    if not verbose:

        sdata = "\n ---- Section Overview (use -v for detailed section info)  ----  \n\n"
        sdata += " {:10}{:12}{:18}{:20}{:20}{:20}{:20}\n".format("Name",
                                                        "Raw Size",
                                                        "Raw Data Pointer",
                                                        "Virtual Address",
                                                        "Virtual Size",
                                                        "Entropy",
                                                        "Hash")

        for section in target.pe.sections:
            sdata += " {:10}".format(section.Name.strip('\0'))
            sdata += "{:12}".format("{0:#0{1}x}".format(section.SizeOfRawData, 10))
            sdata += "{:18}".format("{0:#0{1}x}".format(section.PointerToRawData, 10))
            sdata += "{:20}".format("{0:#0{1}x}".format(section.VirtualAddress, 10))
            sdata += "{:20}".format("{0:#0{1}x}".format(section.Misc_VirtualSize, 10))
            sdata += "{:<20}".format(section.get_entropy())
            sdata += "{:<20}".format(hashlib.md5(section.get_data()).hexdigest())
            sdata += "\n"

    else:
        cflags = pefile.retrieve_flags(pefile.SECTION_CHARACTERISTICS, 'IMAGE_SCN_')

        sdata = '\n ---- Detailed Section Info ----  \n\n'
        for section in target.pe.sections:
            sdata += " {:10}\n".format(section.Name.strip('\0'))
            sdata += "  {:24} {:>10}\n".format("|-Entropy:", section.get_entropy())
            sdata += "  {:24} {:>10}\n".format("|-MD5 Hash:", hashlib.md5(section.get_data()).hexdigest())
            sdata += "  {:24} {:>10} ({:})\n".format("|-Raw Data Size:", "{0:#0{1}x}".format(section.SizeOfRawData, 10),
                                                     section.SizeOfRawData)
            sdata += "  {:24} {:>10}\n".format("|-Raw Data Pointer:", "{0:#0{1}x}".format(section.PointerToRawData, 10))
            sdata += "  {:24} {:>10}\n".format("|-Virtual Address:", "{0:#0{1}x}".format(section.VirtualAddress, 10))
            sdata += "  {:24} {:>10} ({:})\n".format("|-Virtual Size:", "{0:#0{1}x}".format(section.Misc_VirtualSize, 10),
                                                     section.Misc_VirtualSize)
            sdata += "  {:24} {:>10}\n".format("|-Characteristics:", "{0:#0{1}x}".format(section.Characteristics, 10))
            for flag in cflags:
                if getattr(section, flag[0]):
                    sdata += "  {:24}{:>5}{:<24}\n".format('|', '|-', str(flag[0]))
            sdata += "  {:24} {:<10}\n".format("|-Number Of Relocations:", section.NumberOfRelocations)
            sdata += "  {:24} {:<10}\n".format("|-Line Numbers:", section.NumberOfLinenumbers)
            sdata += '\n'
    click.echo(sdata)

@cli.command(context_settings=CONTEXT_SETTINGS)
@click.argument("target")
@click.option("--dumprva", help="RVA for resource to dump")
@click.option("--dumpall", is_flag=True, help="Dump all resources to file")
def resources(target, dumprva, dumpall):
    """Display file resource data"""
    target = PFTriage(target)

    click.echo("\n ---- Resource Overview ----  \n\n")

    try:
        resdir = target.pe.DIRECTORY_ENTRY_RESOURCE
    except AttributeError:
        click.echo('Resources not found...\n')
        return

    for entry in resdir.entries:
        resource_output = ""
        if entry.id is not None:
            try:
                rname = PFTriage.resource_type[entry.id]
            except KeyError:
                rname = "Unknown (%s)" % entry.id
        else:
            # Identified by name
            rname = str(entry.name)

        resource_output = ' Type: %s\n' % rname
        if hasattr(entry, 'directory'):
            resource_output += "  {:12}{:16}{:20}{:12}{:12}{:12}{:64}\n".format("Name",
                                                                "Language",
                                                                "SubLang",
                                                                "Offset",
                                                                "Size",
                                                                "Code Page",
                                                                "Type")

            for resname in entry.directory.entries:
                if resname.id is not None:
                    resource_output += '  {:<12}'.format(hex(resname.id))
                else:
                    resource_output += '  {:<12}'.format(resname.name)

                for resentry in resname.directory.entries:
                    if hasattr(resentry, 'data'):
                        offset = '{0:#0{1}x}'.format(resentry.data.struct.OffsetToData, 10)
                        resource_output += '{:16}'.format(pefile.LANG[resentry.data.lang])
                        resource_output += '{:20}'.format(pefile.get_sublang_name_for_lang(resentry.data.lang,
                                                                                resentry.data.sublang).replace('SUBLANG_', ''))
                        resource_output += '{:12}'.format(offset)
                        resource_output += '{:12}'.format("{0:#0{1}x}".format(resentry.data.struct.Size, 10))
                        resource_output += '{:12}'.format("{0:#0{1}x}".format(resentry.data.struct.CodePage, 10))
                        resource_output += '{:64}'.format(target.magic_type(target.extractdata(resentry.data.struct.OffsetToData,
                                                                                   resentry.data.struct.Size)[:64], True))

                        if dumpall or dumprva == offset:
                            resource_output += '\n\n  Matched offset[%s] -- dumping resource' % offset
                            tmpdata = target.extractdata(resentry.data.struct.OffsetToData, resentry.data.struct.Size)
                            filename = 'export-%s.bin' % offset
                            f = open(filename, 'wb')
                            f.write(tmpdata)
                            f.close()

                resource_output += '\n'
            resource_output += '\n'
        click.echo(resource_output)

@cli.command(context_settings=CONTEXT_SETTINGS)
@click.argument("target")
def analyze(target):
    """Perform a basic analysis on the file"""
    click.echo('[*] Analyzing File...')
    target = PFTriage(target)
    results = target.analyze()
    click.echo('[*] Analysis Complete...')
    if results:
        click.echo("---------------------------------------------------")

        for analysis_result in results:
            if analysis_result.severity == 0:
                click.echo(click.style("[!] %s" % analysis_result.message, fg='red'))
            elif analysis_result.severity == 1:
                click.echo(click.style("[!] %s" % analysis_result.message, fg='yellow'))
            else:
                click.echo("[*] %s" % analysis_result.message)
        click.echo("---------------------------------------------------")
    else:
        click.echo(click.style("[!] No analysis results...", fg='yellow'))

if __name__ == "__main__":
    cli()
