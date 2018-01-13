import re
from email.parser import HeaderParser
import dkim
import dns.resolver
import iptools

# global dictionaries
valid_email_headers = {} # Dictionary of all registered headers and their regex format
headers = {} # Dictionary of all headers/values in email
badheaders = {} # unused for now

def readHeaders():
    with open("/home/A5HW1NR/projects/Header-Checker/header") as f: #file of registered headers with IANA
        content = []
        content = f.readlines()
        content = [item.strip() for item in content]
        for line in content:
            fields = line.split(" ")
            header = fields[0] # header
            if (len(fields) == 2): # check to see if there is a regex
                regex = fields[1] # regex if exists
                valid_email_headers[header] = regex # add regex to value of Dictionary
            else:
                valid_email_headers[header] = "" # no regex available
    return


# function to check if the value of a header matches the correct fomat
# params - header - the header to be checked
#	 - value  - the value to be checked
# returns - true if valid value or false if invalid format
def checkValue(header,value):
    if (valid_email_headers[header] == ""): # is there a regex to be checked against
        return True # valid value
    pattern = re.compile(valid_email_headers[header]) # regex pattern
    print(valid_email_headers[header])
    return re.match(pattern,value) # check if value matches regex

def emailAnalysis():
    print("Input original email file.\n")
    filename = input()
    with open(filename) as f:
        content = []
        newlist = []
        content = f.readlines()
        last = "" # create variable for last element
        for item in content:
            if item[0] == " ": # checks for multi lined headers
                last = last.strip() + item # adds the multi line headers to one line
            else:
                newlist.append(last)
                last = item

        newlist.append(last)

        for line in newlist:
            if line in ['\n','\r\n']: # break out once you hit the email contents
                break
            elif ":" not in line: # don't add lines to the header doct without a :, all headers are [HEADER}: [VALUE]
                continue
            else:
                fields = line.split(':',1) # split on the first : in each line
                header = fields[0]
                value = fields[1]
                if header not in valid_email_headers.keys(): # is the header registered with IANA
                    print("Found header not registered with IANA:", header,":",value) # it is not
                else:
                    if not (checkValue(header,value)): # is the value correctly formatted
                        print("Valid header but invalid formatted value:", header,":",value)
                headers[header] = value # add header/value to dictionary
    return filename

def testDKIM(filename):
    with open(filename, 'rb') as f:
        rawemail = f.read()
        d = dkim.DKIM(rawemail)
        try:
            return d.verify()
        except dkim.ValidationError:
            return False

def testSPF(headers):
    #spf is txt records
    #validate return-path
    #lets check from too just as a warning situation
    #not meant for testing for authenticity
    # domain.com txt
    # broken from forwarding can we check this? can we just avoid these checks by doing somethings that shows forwarding?
    recievedheaders = []
    successes = set()
    failures = set()
    returnpath = None
    for header in headers.items():
        if header[0] == 'Return-Path':
            returnpath = header[1]
        elif header[0] == 'Received':
            recievedheaders.append(header)

    if returnpath is not None:
        domain = returnpath.split('@')[1][:-1]
        ips = pullSpfRecords(domain)
        if ips:
            ipranges = iptools.IpRangeList(*ips)
            for header in recievedheaders:
                valuelist = header[1].split()
                if valuelist[1][-1].isdigit():
                    if valuelist[1] in ipranges:
                        successes.add(valuelist[1])
                    else:
                        failures.add(valuelist[1])
                else:
                    try:
                        ans = dns.resolver.query(valuelist[1], 'A')
                        for rdata in ans:
                            rdata = rdata.address
                            if rdata in ipranges:
                                successes.add(rdata)
                                successes.add(valuelist[1])
                            else:
                                failures.add(rdata)
                                failures.add(valuelist[1])
                    except dns.resolver.NXDOMAIN:
                        failures.add(valuelist[1])


        print('Failed SPF received ips {}'.format(failures))
        print('Succeeded SPF received ips {}'.format(successes))
        if successes:
            return True
        elif failures:
            return False
        return 'No ips in SPF records' #TODO needs to not be this considering true or false elsewhere

def pullSpfRecords(domain):
    """ gets the domains txt records and finds the spf record """
    ans = dns.resolver.query(domain, 'TXT')
    for record in ans:
        for txtdata in record.strings:
            stringdata = txtdata.decode("utf-8")
            if stringdata.startswith('v=spf1'):
                return pullIpsFromSpfRecord(stringdata)

    return []

def pullIpsFromSpfRecord(spftextstring):
    """ parses spf txt record and gets all ips allowed """
    splitdata = spftextstring.split()
    ips = []
    for string in splitdata:
        if ':' in string:
            splitstring = string.split(':')
            if splitstring[0] == 'ip4':
                ips.append(splitstring[1])
            elif splitstring[0] == 'ip6':
                ips.append(splitstring[1])
            elif splitstring[0] == 'include':
                ips += pullSpfRecords(splitstring[1])
            elif splitstring[0] == 'redirect':
                ips = []
                pullSpfRecords(splitstring[1])
            elif splitstring[0] == 'mx':
                pass #unsure what to do here.
    return ips

def readAuthHeaders(filename):
    with open(filename) as f:
        parser = HeaderParser()
        h = parser.parse(f)

        '''
        print('headers: {}'.format(len(h.items())))
        for header in h.items():
            print('NEW')
            print(header)
        '''
        print('spf test: {}'.format(testSPF(h)))

def testDMARC():
    #_dmarc . domain
    #call the other two tests
    pass

def main(filename=None):
    if not filename:
        readHeaders()
        filename = emailAnalysis()
    print('dkim test: {}'.format(testDKIM(filename)))
    print('spf test: {}'.format(testSPF())
    readAuthHeaders(filename)

if __name__ == '__main__':
    main()

main()
