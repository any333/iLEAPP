import plistlib
from re import search, findall, DOTALL

from scripts.artifact_report import ArtifactHtmlReport
from scripts.ilapfuncs import logfunc, tsv, timeline, is_platform_windows


def get_keychainAll(files_found, report_folder, seeker):
    data_list = []

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
            generic_passwords_content = extract_file_content(file_found)
            generic_passwords = find_all_entries('Generic Password', 'Generic Password', generic_passwords_content)

            for generic_password in generic_passwords:
                service = find_specific_entry('Service: ', '\n', generic_password)
                account = find_specific_entry('Account: ', '\n', generic_password)
                entitlement = find_specific_entry('Entitlement Group: ', '\n', generic_password)
                label = find_specific_entry('Label: ', '\n', generic_password)
                accessible_attribute = find_specific_entry('Accessible Attribute: ', '\n', generic_password)
                description = find_specific_entry('Description: ', '\n', generic_password)
                comment = find_specific_entry('Comment: ', '\n', generic_password)
                synchronizable = find_specific_entry('Synchronizable: ', '\n', generic_password)
                generic_field = find_specific_entry('Generic Field: ', '\n', generic_password)
                if search('Hex', generic_password):
                    keychain_data_hex = find_specific_entry('Keychain Data \(Hex\): ', '\n', generic_password)
                    keychain_data = ''
                else:
                    keychain_data = find_specific_entry('Keychain Data: ', '\n', generic_password)
                    keychain_data_hex = ''

                data_list.append((service, account, entitlement, label, accessible_attribute, description, comment,
                                  synchronizable, generic_field, keychain_data, keychain_data_hex))

            if len(data_list) > 0:
                report = ArtifactHtmlReport('Generic Passwords')
                report.start_artifact_report(report_folder, 'Generic Passwords')
                report.add_script()
                data_headers = ('Service', 'Account', 'Entitlement Group', 'Label', 'Accessible Attribute',
                                'Description', 'Comment', 'Synchronizable', 'Generic Field', 'Keychain Data',
                                'Keychain Data (Hex)')
                report.write_artifact_data_table(data_headers, data_list, file_found)
                report.end_artifact_report()

                tsvname = 'Keychain Generic Passwords'
                tsv(report_folder, data_headers, data_list, tsvname)

                tlactivity = 'Generic Passwords'
                timeline(report_folder, tlactivity, data_list, data_headers)

                data_list.clear()

            else:
                logfunc('No data available for Keychain - Generic Passwords')

        elif search('internet_passwords', file_found_lower):
            internet_passwords_content = extract_file_content(file_found)
            internet_passwords = find_all_entries('Internet Password', 'Internet Password', internet_passwords_content)

            for internet_password in internet_passwords:
                server = find_specific_entry('Server: ', '\n', internet_password)
                account = find_specific_entry('Account: ', '\n', internet_password)
                entitlement = find_specific_entry('Entitlement Group: ', '\n', internet_password)
                label = find_specific_entry('Label: ', '\n', internet_password)
                accessible_attribute = find_specific_entry('Accessible Attribute: ', '\n', internet_password)
                if search('Hex', internet_password):
                    keychain_data_hex = find_specific_entry('Keychain Data \(Hex\): ', '\n', internet_password)
                    keychain_data = ''
                else:
                    keychain_data = find_specific_entry('Keychain Data: ', '\n', internet_password)
                    keychain_data_hex = ''

                data_list.append(
                    (server, account, entitlement, label, accessible_attribute, keychain_data, keychain_data_hex))

            if len(data_list) > 0:
                report = ArtifactHtmlReport('Internet Passwords')
                report.start_artifact_report(report_folder, 'Internet Passwords')
                report.add_script()
                data_headers = ('Server', 'Account', 'Entitlement Group', 'Label', 'Accessible Attribute', 'Keychain Data', 'Keychain data (Hex)')
                report.write_artifact_data_table(data_headers, data_list, file_found)
                report.end_artifact_report()

                tsvname = 'Keychain Internet Passwords'
                tsv(report_folder, data_headers, data_list, tsvname)

                tlactivity = 'Internet Passwords'
                timeline(report_folder, tlactivity, data_list, data_headers)

                data_list.clear()

            else:
                logfunc('No data available for Keychain - Internet Passwords')

        elif search('identities', file_found_lower):
            data_list.append((newline_to_br(extract_file_content(file_found)),))

            if len(data_list) > 0:
                report = ArtifactHtmlReport('Identities')
                report.start_artifact_report(report_folder, 'Identities')
                report.add_script()
                data_headers = ('Found Identities',)
                report.write_artifact_data_table(data_headers, data_list, file_found,
                                                 html_no_escape=['Found Identities'])
                report.end_artifact_report()

                tsvname = 'Keychain Identities'
                tsv(report_folder, data_headers, data_list, tsvname)

                tlactivity = 'Identities'
                timeline(report_folder, tlactivity, data_list, data_headers)

                data_list.clear()

            else:
                logfunc('No data available for Keychain - Identities')

        elif search('certificates', file_found_lower):
            certificates_content = extract_file_content(file_found)
            certificates = find_all_entries('Certificate', 'Certificate', certificates_content)

            for certificate in certificates:
                summary = find_specific_entry('Summary: ', '\n', certificate)
                entitlement = find_specific_entry('Entitlement Group: ', '\n', certificate)
                label = find_specific_entry('Label: ', '\n', certificate)
                accessible_attribute = find_specific_entry('Accessible Attribute: ', '\n', certificate)
                serial_number = find_specific_entry('Serial Number: ', '\n', certificate)
                subject_key_id = find_specific_entry('Subject Key ID: ', '\n', certificate)
                subject_key_hash = find_specific_entry('Subject Key Hash: ', '\n', certificate)
                cert = newline_to_br(find_specific_entry('\n\n', '\n\n', certificate))

                data_list.append((
                                 cert, summary, entitlement, label, accessible_attribute, serial_number, subject_key_id,
                                 subject_key_hash))

            if len(data_list) > 0:
                report = ArtifactHtmlReport('Certificates')
                report.start_artifact_report(report_folder, 'Certificates')
                report.add_script()
                data_headers = ('Certificate', 'Summary', 'Entitlement Group', 'Label', 'Accessible Attribute',
                                'Serial Number', 'Serial Key ID', 'Serial Key Hash')
                report.write_artifact_data_table(data_headers, data_list, file_found, html_no_escape=['Certificate'])
                report.end_artifact_report()

                tsvname = 'Keychain Certificates'
                tsv(report_folder, data_headers, data_list, tsvname)

                tlactivity = 'Certificates'
                timeline(report_folder, tlactivity, data_list, data_headers)

                data_list.clear()

            else:
                logfunc('No data available for Keychain - Certificates')

        elif search('keys', file_found_lower):
            keys_content = extract_file_content(file_found)
            keys = find_all_entries('Key', 'Key\n-', keys_content)

            for key in keys:
                entitlement = find_specific_entry('Entitlement Group: ', '\n', key)
                label = find_specific_entry('Label: ', '\n', key)
                accessible_attribute = find_specific_entry('Accessible Attribute: ', '\n', key)
                app_label = find_specific_entry('Application Label: ', '\n', key)
                app_tag = find_specific_entry('Application Tag: ', '\n', key)
                key_class = find_specific_entry('Key Class: ', '\n', key)
                key_size = find_specific_entry('Key Size: ', '\n', key)
                effective_key_size = find_specific_entry('Effective Key Size: ', '\n', key)

                if not search('INFO', key):
                    info = ''
                    permanent_key = find_specific_entry('Permanent Key: ', '\n', key)
                    encryption = find_specific_entry('For Encryption: ', '\n', key)
                    decryption = find_specific_entry('For Decryption: ', '\n', key)
                    key_derivation = find_specific_entry('For Key Derivation: ', '\n', key)
                    signatures = find_specific_entry('For Signatures: ', '\n', key)
                    signature_verification = find_specific_entry('For Signature Verification: ', '\n', key)
                    key_wrapping = find_specific_entry('For Key Wrapping: ', '\n', key)
                    key_unwrapping = find_specific_entry('For Key Unwrapping: ', '\n', key)
                    key_data = newline_to_br(find_specific_entry('key data:\n', '\n\n', key))
                else:
                    info = find_specific_entry('\[INFO\] ', '\n', key)
                    permanent_key = encryption = decryption = key_derivation = signatures = \
                        signature_verification = key_wrapping = key_unwrapping = key_data = ''

                data_list.append((key_data, key_class, key_size, effective_key_size, permanent_key, encryption,
                                  decryption, key_derivation, signatures, signature_verification, entitlement, label,
                                  accessible_attribute, app_label, app_tag, key_wrapping, key_unwrapping, info))

            if len(data_list) > 0:
                report = ArtifactHtmlReport('Keys')
                report.start_artifact_report(report_folder, 'Keys')
                report.add_script()
                data_headers = ('Key Data', 'Class', 'Size', 'Effective Size', 'Is Permanent', 'For Encryption',
                                'For Decryption', 'For Key Derrivation', 'For Signatures', 'For Signature Verification',
                                'Entitlement Group', 'Label', 'Accessible Attribute', 'Application Label',
                                'Application Tag', 'For Key Wrapping', 'For Key Wrapping', 'Info')
                report.write_artifact_data_table(data_headers, data_list, file_found, html_no_escape=['Key Data'])
                report.end_artifact_report()

                tsvname = 'Keychain Keys'
                tsv(report_folder, data_headers, data_list, tsvname)

                tlactivity = 'Keys'
                timeline(report_folder, tlactivity, data_list, data_headers)

                data_list.clear()

            else:
                logfunc('No data available for Keychain - Keys')

        if search('generic_passwords', file_found_lower):
            generic_passwords_content = extract_file_content(file_found)
            generic_passwords = find_all_entries('Service: AirPort', 'Generic Password', generic_passwords_content)

            for generic_password in generic_passwords:
                service = 'AirPort'
                account = find_specific_entry('Account: ', '\n', generic_password)
                entitlement = find_specific_entry('Entitlement Group: ', '\n', generic_password)
                keychain_data = find_specific_entry('Keychain Data: ', '\n', generic_password)

                data_list.append((service, account, entitlement, keychain_data))

            if len(data_list) > 0:
                report = ArtifactHtmlReport('Wi-Fi Passwords')
                report.start_artifact_report(report_folder, 'Wi-Fi Passwords')
                report.add_script()
                data_headers = ('Service', 'Connection Name', 'Entitlement Group', 'Password')
                report.write_artifact_data_table(data_headers, data_list, file_found)
                report.end_artifact_report()

                tsvname = 'Wi-Fi Passwords'
                tsv(report_folder, data_headers, data_list, tsvname)

                tlactivity = 'Wi-Fi Passwords'
                timeline(report_folder, tlactivity, data_list, data_headers)

                data_list.clear()


def newline_to_br(string):
    return string.replace('\n', '<br />')


def extract_file_content(file):
    with open(file, 'rb') as file:
        file_content = file.read()
        return str(file_content, 'utf-8', 'ignore')


def find_all_entries(starting_str, ending_str, search_field):
    regex = '(?<={start})(.*?)(?={end})'.format(start=starting_str, end=ending_str)
    entries = findall(regex, search_field, flags=DOTALL)
    return entries


def find_specific_entry(starting_str, ending_str, search_field):
    regex = '(?<={start})(.*?)(?={end})'.format(start=starting_str, end=ending_str)
    entry = search(regex, search_field, flags=DOTALL).group(0)
    return entry
