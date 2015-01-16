import requests
import json
import base64
import prettytable

ip           = "10.52.208.111"
username     = "api"
password     = "api$1234"

ip2          = "10.52.208.112"
username2    = "api"
password2    = "api$1234"

color_red    = "\x1b[31;01m"
color_green  = "\x1b[00;32m"
color_blue   = "\x1b[34;01m"
color_normal = "\x1b[00m"

# No underscores = public function and or variable
# _  = local class function, only to be called within the class
# __ = local class variable, only used within the class


class nxapiFunctions:
    def compareVersions( self, version1, version2 ):
        pass

    def _getConfigItem( self, config, items ):
        tmp = ""
        if( type( items ) == list ):
            tmp = items[ 0 ]
            tmp2 = ""
            if( tmp in config ):
                for a in items:
                    tmp2 += "[ \"" + a + "\" ]"
                return( eval( "config" + tmp2 ))
        return None

    def compareVPCConfigs( self, config1, config2, output = True ):
        print( color_blue + "********Comparing VPC Configs********************" )

        interface1 = config1[ "body" ][ "filter" ][ "configure" ][ "terminal" ][ "interface" ][ "__XML__PARAM__interface" ]
        interface2 = config2[ "body" ][ "filter" ][ "configure" ][ "terminal" ][ "interface" ][ "__XML__PARAM__interface" ]

        spanningtree = [ "spanning-tree", "port", "type", "__XML__PARAM__port-type", "__XML__value" ]
        description = [ "description", "__XML__PARAM__desc_line", "__XML__value" ]
        mode = [ "switchport", "mode", "__XML__PARAM__port_mode", "__XML__value" ]
        name = [ "__XML__value" ]
        vpc = [ "vpc", "peer-link" ]

        span1 = self._getConfigItem( interface1, spanningtree )
        span2 = self._getConfigItem( interface2, spanningtree )
        desc1 = self._getConfigItem( interface1, description )
        desc2 = self._getConfigItem( interface2, description )
        mode1 = self._getConfigItem( interface1, mode )
        mode2 = self._getConfigItem( interface2, mode )
        vpc1  = self._getConfigItem( interface1, vpc )
        vpc2  = self._getConfigItem( interface2, vpc )

        score = 0
        result = ""

        if( span1  == span2 ):
            result += "Spanning Tree config's match.\n"
            score  += 25
        else:
            result += "Spanning Tree configs are different, one is configured as %s and the other as %s.\n" % ( span1, span2 )

        if( desc1  == desc2 ):
            result += "The descriptions match.\n"
            score  += 25
        else:
            result += "The descriptions are different on the two devices.\n"

        if( mode1  == mode2 ):
            result += "The interface modes match.\n"
            score  += 25
        else:
            result += "The interface modes do not match, one is configured as %s and the other as %s.\n" % ( mode1, mode2 )

        if( vpc1   == vpc2 ):
            result += "The VPC Peer-Link matches."
            score  += 25
        else:
            result += "The VPC Peer-Link configs do not match."

        if( output ):
            print( result )

        return color_green + str( score ) + "% of VPC config matches."

    def formatInterfaces( self, json ):
        pt = prettytable.PrettyTable(["Interface", "Mode", "State", "Vlan", "Speed", "PO", "Type"])
        for a in json:
            if( "Ethernet" in a[ "interface" ] ):
                if( "portchan" in a ):
                    po = a[ "portchan" ]
                else:
                    po = "0"
                pt.add_row([ a[ "interface" ], a[ "portmode" ], a[ "state" ], a[ "vlan" ], a[ "speed" ], po, a[ "type" ]])
        return str( pt )


class nxapi:
    __url            = None
    __username       = None
    __password       = None
    __token          = None
    __lastStatus     = None
    __lastResponse   = None
    __lastOutput     = None
    __lastBody       = None
    __fetch_SID      = "session1"
    __fetch_Version  = "0.1"
    __fetch_Op       = None
    __devicePlatform = None
    __deviceHostname = None
    __deviceVersion  = None
    __deviceSerial   = None
    __deviceUptime   = None
    functions        = nxapiFunctions()

    def __init__( self, ip = None, username = None, password = None, output = True ):
        self.__url      = ip
        self.__username = username
        self.__password = password
        self.__token    = self._CreateAuthHeader()
        self.setFetchOperation( "cli_show" )
        self.fetch( "show version" )
        self._getPlatformInfo( self.__lastBody, output )

    def setFetchOperation( self, operation ):
        self.__fetch_Op = operation

    def _stringToBase64( self, s ):
        try:
            return base64.encodestring( s.encode( "utf-8" ))[:-1]
        except Exception as e:
            print( e )

    def _CreateAuthHeader( self ):
        try:
            return self._stringToBase64( self.__username + ":" + self.__password )
        except Exception as e:
            print( e )

    def _getOutputFromJson( self, response ):
        try:
            j = json.loads( response )
            return j[ "ins_api" ][ "outputs" ][ "output" ]
        except Exception as e:
            print( "No data to process!  Exiting" )
            exit()

    def _getOutputCommandInput( self, output ):
        return self._getOutputCommandCustom( output, "input" )

    def _getOutputCommandCode( self, output ):
        return self._getOutputCommandCustom( output, "code" )

    def _getOutputCommandMessage( self, output ):
        return self._getOutputCommandCustom( output, "msg" )

    def _getOutputCommandOutput( self, output ):
        return self._getOutputCommandCustom( output, "body" )

    def _getOutputCommandCustom( self, output, field ):
        try:
            if( type( field ) == list ):
                if( len( field ) == 2 ):
                    return output[ field[ 0 ]][ field[ 1 ]]
            else:
                if( field in output ):
                    return output[ field ]
        except Exception as e:
            print( e.msg )
            print( "No data to process!  Exiting" )
            exit()

    def _sendRequest( self, command ):
        try:
            token = bytes.decode( self.__token )
            data = "{ \"ins_api\": { \"version\": \"" + self.__fetch_Version + "\", \"type\": \"" + self.__fetch_Op + "\", \"chunk\": \"0\", \"sid\": \"" + self.__fetch_SID + "\", \"input\": \"" + command + "\", \"output_format\": \"json\"}}"
            headers = { "Authorization" : "Basic %s" % ( token ) }
            r = requests.post( url="http://" + self.__url + "/ins/", headers = headers, data = data )
            code = r.status_code
            response = bytes.decode( r.content )
            return str( code ), response
        except requests.exceptions.RequestException as e:
            print('HTTP Request failed')
            exit()

    def _getPlatformInfo( self, output, display ):
        try:
            if( output != None ):
                if( "msg" in output ):
                    if( self._getOutputCommandCustom( output, "msg" ) == "Permission denied" or self._getOutputCommandCustom( "code" ) == "401" ):
                        print( "No LUCK" )
                else:
                    self.__devicePlatform = self._getOutputCommandCustom( output, "chassis_id" )
                    self.__deviceHostname = self._getOutputCommandCustom( output, "host_name" )
                    self.__deviceVersion  = self._getOutputCommandCustom( output, "kickstart_ver_str" )
                    self.__deviceSerial   = self._getOutputCommandCustom( output, "proc_board_id" )
                    self.__deviceUptime   = ( "%s days %s hours %s mins %s secs" ) % ( self._getOutputCommandCustom( output, "kern_uptm_days" ), self._getOutputCommandCustom( output, "kern_uptm_hrs" ), self._getOutputCommandCustom( output, "kern_uptm_mins" ), self._getOutputCommandCustom( output, "kern_uptm_secs" ))
                    if( display != None and display != False ):
                        print( color_green + "**** Connected to platform at: %s ****" % self.__url )
                        print( "Platform:         %s" % self.__devicePlatform )
                        print( "Hostname:         %s" % self.__deviceHostname )
                        print( "Software Version: %s" % self.__deviceVersion )
                        print( "Serial Number:    %s" % self.__deviceSerial )
                        print( "Uptime:           %s" % self.__deviceUptime )
        except Exception as e:
            print( e )
            print( "No data to process!  Exiting" )
            exit()

    def _debug( self, output ):
        print( "Command sent:    %s" % self._getOutputCommandInput( output ))
        print( "Command Code:    %s" % self._getOutputCommandCode( output ))
        print( "Command Message: %s" % self._getOutputCommandMessage( output ))
        print( "Command Output:  %s" % self._getOutputCommandOutput( output ))

    def fetch( self, command ):
        self.__lastStatus, self.__lastResponse = self._sendRequest( command )
        self.__lastOutput = self._getOutputFromJson( self.__lastResponse )
        self.__lastBody = self._getOutputCommandOutput( self.__lastOutput )

    def getPlatform( self ):
        return self.__devicePlatform

    def getPlatformHostname( self ):
        return self.__deviceHostname

    def getPlatformVersion( self ):
        return self.__deviceVersion

    def getPlatformSerial( self ):
        return self.__deviceSerial

    def getPlatformUptime( self ):
        return self.__deviceUptime

    def getLastStatus( self ):
        return self.__lastStatus

    def getLastResponse( self ):
        return self.__lastResponse

    def getLastOutput( self ):
        return self.__lastOutput

    def getLastBody( self ):
        return self.__lastBody

    def getInterfaceBrief( self ):
        self.fetch( "show int br" )
        return self.functions.formatInterfaces( self._getOutputCommandCustom( self.getLastBody(), [ "TABLE_interface", "ROW_interface" ]))

    def getVPCConfig( self ):
        self.fetch( "show vpc br" )

    def getVPCPeerLink( self ):
        self.fetch( "show vpc statistics peer-link" )

    def getVPCRunPOConfig( self ):
        self.fetch( "show run int po 2" )

    def getVPCPOConfig( self ):
        self.fetch( "show int po 2" )

    def compareVPCConfigs( self, config2, output ):
        self.getVPCRunPOConfig()
        return( self.functions.compareVPCConfigs( self.getLastOutput(), config2, output ))

print( color_blue + "********Connecting to device 1*******************" )
inst1     = nxapi( ip, username, password, True )
print( color_blue + "********Connecting to device 2*******************" )
inst2     = nxapi( ip2, username2, password2, True )

print( color_blue + "********Getting VPC Port Channel Config 1********" )
inst2.getVPCRunPOConfig()
print( color_blue + "********Getting VPC Port Channel Config 2********" )
print( inst1.compareVPCConfigs( inst2.getLastOutput(), False ))
