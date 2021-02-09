import plistlib
from re import search

from scripts.artifact_report import ArtifactHtmlReport
from scripts.ilapfuncs import logfunc, tsv, timeline, is_platform_windows


def get_keychainAll(files_found, report_folder, seeker):
    data_list = []

    print(files_found)

    for file_found in files_found:
        file_found = str(file_found)
        file_found_lower = file_found.lower()

        if search('entitlements', file_found_lower):
            with open(file_found, "rb") as file:
                file_content = plistlib.load(file)
                for entry in file_content['keychain-access-groups']:
                    data_list.append((entry,))

            if len(data_list) > 0:
                report = ArtifactHtmlReport('Entitlements')
                report.start_artifact_report(report_folder, 'Entitlements')
                report.add_script()
                data_headers = ('Keychain Access Groups',)
                report.write_artifact_data_table(data_headers, data_list, file_found)
                report.end_artifact_report()

                tsvname = 'Keychain Entitlements'
                tsv(report_folder, data_headers, data_list, tsvname)

                tlactivity = 'Entitlements'
                timeline(report_folder, tlactivity, data_list, data_headers)

                data_list.clear()

            else:
                logfunc('No data available for Keychain - Entitlements')

        elif search('generic_passwords', file_found_lower):
            data_list.append((extract_file_content(file_found),))

            if len(data_list) > 0:
                report = ArtifactHtmlReport('Generic Passwords')
                report.start_artifact_report(report_folder, 'Generic Passwords')
                report.add_script()
                data_headers = ('Found Generic Passwords',)
                report.write_artifact_data_table(data_headers, data_list, file_found, html_no_escape=['Found Generic Passwords'])
                report.end_artifact_report()

                tsvname = 'Keychain Generic Passwords'
                tsv(report_folder, data_headers, data_list, tsvname)

                tlactivity = 'Generic Passwords'
                timeline(report_folder, tlactivity, data_list, data_headers)

                data_list.clear()

            else:
                logfunc('No data available for Keychain - Generic Passwords')

        elif search('internet_passwords', file_found_lower):
            data_list.append((extract_file_content(file_found),))

            if len(data_list) > 0:
                report = ArtifactHtmlReport('Internet Passwords')
                report.start_artifact_report(report_folder, 'Internet Passwords')
                report.add_script()
                data_headers = ('Found Internet Passwords',)
                report.write_artifact_data_table(data_headers, data_list, file_found, html_no_escape=['Found Internet Passwords'])
                report.end_artifact_report()

                tsvname = 'Keychain Internet Passwords'
                tsv(report_folder, data_headers, data_list, tsvname)

                tlactivity = 'Internet Passwords'
                timeline(report_folder, tlactivity, data_list, data_headers)

                data_list.clear()

            else:
                logfunc('No data available for Keychain - Internet Passwords')

        elif search('identities', file_found_lower):
            data_list.append((extract_file_content(file_found),))

            if len(data_list) > 0:
                report = ArtifactHtmlReport('Identities')
                report.start_artifact_report(report_folder, 'Identities')
                report.add_script()
                data_headers = ('Found Identities',)
                report.write_artifact_data_table(data_headers, data_list, file_found, html_no_escape=['Found Identities'])
                report.end_artifact_report()

                tsvname = 'Keychain Identities'
                tsv(report_folder, data_headers, data_list, tsvname)

                tlactivity = 'Identities'
                timeline(report_folder, tlactivity, data_list, data_headers)

                data_list.clear()

            else:
                logfunc('No data available for Keychain - Identities')

        elif search('certificates', file_found_lower):
            data_list.append((extract_file_content(file_found),))

            if len(data_list) > 0:
                report = ArtifactHtmlReport('Certificates')
                report.start_artifact_report(report_folder, 'Certificates')
                report.add_script()
                data_headers = ('Found Certificates',)
                report.write_artifact_data_table(data_headers, data_list, file_found, html_no_escape=['Found Certificates'])
                report.end_artifact_report()

                tsvname = 'Keychain Certificates'
                tsv(report_folder, data_headers, data_list, tsvname)

                tlactivity = 'Certificates'
                timeline(report_folder, tlactivity, data_list, data_headers)

                data_list.clear()

            else:
                logfunc('No data available for Keychain - Certificates')

        elif search('keys', file_found_lower):
            data_list.append((extract_file_content(file_found),))

            if len(data_list) > 0:
                report = ArtifactHtmlReport('Keys')
                report.start_artifact_report(report_folder, 'Keys')
                report.add_script()
                data_headers = ('Found Keys',)
                report.write_artifact_data_table(data_headers, data_list, file_found, html_no_escape=['Found Keys'])
                report.end_artifact_report()

                tsvname = 'Keychain Keys'
                tsv(report_folder, data_headers, data_list, tsvname)

                tlactivity = 'Keys'
                timeline(report_folder, tlactivity, data_list, data_headers)

                data_list.clear()

            else:
                logfunc('No data available for Keychain - Keys')


def br_instead_of_newline(string):
    return string.replace('\n', '<br />')


def extract_file_content(file):
    with open(file, 'rb') as file:
        file_content = file.read()
        return br_instead_of_newline(str(file_content, 'utf-8', 'ignore'))



