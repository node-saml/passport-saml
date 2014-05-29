'use strict';
var express      = require( 'express' );
var bodyParser   = require( 'body-parser' );
var passport     = require( 'passport' );
var SamlStrategy = require( '../lib/passport-saml/index.js' ).Strategy;
var request      = require( 'request' );
var should       = require( 'should' );
var zlib         = require( 'zlib' );
var querystring  = require( 'querystring' );
var parseString  = require( 'xml2js' ).parseString;
var SAML         = require( '../lib/passport-saml/saml.js' ).SAML;

describe( 'passport-saml /', function() {
  describe( 'captured saml responses /', function() {
    var capturedChecks = [
      { name: 'Okta -- valid config should succeed',
        samlResponse: { 
          SAMLResponse: 'PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOlJlc3BvbnNlIHhtbG5zOnNhbWwycD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiBEZXN0aW5hdGlvbj0iaHR0cDovL2xvY2FsaG9zdC9icm93c2VyU2FtbExvZ2luIiBJRD0iaWQzMzcxMDA5NzQ3ODg2OTIzMjIwMzA1Njc3ODMiIEluUmVzcG9uc2VUbz0iXzVjMzg1YWJiMTc3MzViN2FhOGQxIiBJc3N1ZUluc3RhbnQ9IjIwMTQtMDUtMjdUMjM6Mjc6MzUuNDI2WiIgVmVyc2lvbj0iMi4wIj48c2FtbDI6SXNzdWVyIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OmVudGl0eSI+aHR0cDovL3d3dy5va3RhLmNvbS9rdmpqNDZsc0RRRVFZVURCWklZVzwvc2FtbDI6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPjxkczpSZWZlcmVuY2UgVVJJPSIjaWQzMzcxMDA5NzQ3ODg2OTIzMjIwMzA1Njc3ODMiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+PGRzOkRpZ2VzdFZhbHVlPjRSNUNjYUVEQ3dPSCtudnVHSkY3TWRBelpIdz08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU+TzlycW1TUTJQd1NaZDFBeklRUDUySkY5VHBaSkJUNENpdnAxTUZZN3FzODdrU2RFQ3dNbWFWTDE2NFI4dUlCbzdscXUwOFRaTGZYeGF6ak5uRDhnV05BOWRuK2d5cFc1ZWo4S3EzK1J3cUxZUzM1M3pCeVpWcy9MSUxQZVJCK0tUS2RsbTVJSDcxdWhwbUp4a3k0T0gwNWdDSWExYnRFaXpKV1h3d1lleXpBPTwvZHM6U2lnbmF0dXJlVmFsdWU+PGRzOktleUluZm8+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJQ29UQ0NBZ3FnQXdJQkFnSUdBVVk4elZQWU1BMEdDU3FHU0liM0RRRUJCUVVBTUlHVE1Rc3dDUVlEVlFRR0V3SlZVekVUTUJFRwpBMVVFQ0F3S1EyRnNhV1p2Y201cFlURVdNQlFHQTFVRUJ3d05VMkZ1SUVaeVlXNWphWE5qYnpFTk1Bc0dBMVVFQ2d3RVQydDBZVEVVCk1CSUdBMVVFQ3d3TFUxTlBVSEp2ZG1sa1pYSXhGREFTQmdOVkJBTU1DM04xWW5Od1lXTmxjM2N4TVJ3d0dnWUpLb1pJaHZjTkFRa0IKRmcxcGJtWnZRRzlyZEdFdVkyOXRNQjRYRFRFME1EVXlOekE0TWpreU4xb1hEVFEwTURVeU56QTRNekF5TjFvd2daTXhDekFKQmdOVgpCQVlUQWxWVE1STXdFUVlEVlFRSURBcERZV3hwWm05eWJtbGhNUll3RkFZRFZRUUhEQTFUWVc0Z1JuSmhibU5wYzJOdk1RMHdDd1lEClZRUUtEQVJQYTNSaE1SUXdFZ1lEVlFRTERBdFRVMDlRY205MmFXUmxjakVVTUJJR0ExVUVBd3dMYzNWaWMzQmhZMlZ6ZHpFeEhEQWEKQmdrcWhraUc5dzBCQ1FFV0RXbHVabTlBYjJ0MFlTNWpiMjB3Z1o4d0RRWUpLb1pJaHZjTkFRRUJCUUFEZ1kwQU1JR0pBb0dCQUtZWAovVWRWOUhMWGJOS3YweWM2WUpCdHpkV051R1RQSVhXVlBDYjBPc1J2UjU0bHErMFNMUFFHSlMzOWZsV0tpcXRVaUV1c3VpaDZHZExmCk52RkFWTEdQcUJUV1E0TGM3cjUrekQ1cW5INkxpVE0xS0NiYUYzdXUyUCtUK3V0c0dxRlVaYXdBOUZFVk5Ma0lDZTM2WDF5RTQwWCsKL2pNeWd5aWVRUE1lSkFCdkFnTUJBQUV3RFFZSktvWklodmNOQVFFRkJRQURnWUVBSFNXUEc0eTFiTnlKeVNnYkZxRGNTLzZNVU5JcgpTZmtRWUl4eklHUTM3cXk1cUFXMTVZa0JVaVc5VHNHSlJjcmd1c1ZyWklpYTE4ZVl6ODRabjdGeVVaTk1GbzI0TDdsNkJTMFdDaXRJClFTY0JDS0I0UVdBL2Ixc3pxczdFdHBPY1BQMDFUWU5xMnJhcytWcVIzYVdBWExYMm9LZkNsVi9TVXdzelJmNVU4NVk9PC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8+PC9kczpTaWduYXR1cmU+PHNhbWwycDpTdGF0dXMgeG1sbnM6c2FtbDJwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPjxzYW1sMnA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIi8+PC9zYW1sMnA6U3RhdHVzPjxzYW1sMjpBc3NlcnRpb24geG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIElEPSJpZDMzNzEwMDk3NDc4OTQ5MTAwNjY2NTIyNTEyIiBJc3N1ZUluc3RhbnQ9IjIwMTQtMDUtMjdUMjM6Mjc6MzUuNDI2WiIgVmVyc2lvbj0iMi4wIj48c2FtbDI6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5IiB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+aHR0cDovL3d3dy5va3RhLmNvbS9rdmpqNDZsc0RRRVFZVURCWklZVzwvc2FtbDI6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPjxkczpSZWZlcmVuY2UgVVJJPSIjaWQzMzcxMDA5NzQ3ODk0OTEwMDY2NjUyMjUxMiI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48ZHM6RGlnZXN0VmFsdWU+UFM4dE5taVVZUXpRQVFURjh3RDFRT3dMazA0PTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5XM3JiUkNFUmE1ZEtUcy9MSERwY0pEeUhjSzFESjczd2xhT3J2MXZWNmZxQ3FTTUNpclZLRVlLKzR2OG5WaThZNlZwcVJHd0trWFV2cUY0b0hKWjYzOE5YYVRiRVRjU1VXWjVUNXowbzBNVXhBL3RnL01zVzYvRlVRMXBqUWJhVlhJT3Mvc1EwVzluUXpmZkVZLzgrSkVJMldLY0I2UkZlVzVtTlkvdm9oUWM9PC9kczpTaWduYXR1cmVWYWx1ZT48ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlDb1RDQ0FncWdBd0lCQWdJR0FVWTh6VlBZTUEwR0NTcUdTSWIzRFFFQkJRVUFNSUdUTVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHCkExVUVDQXdLUTJGc2FXWnZjbTVwWVRFV01CUUdBMVVFQnd3TlUyRnVJRVp5WVc1amFYTmpiekVOTUFzR0ExVUVDZ3dFVDJ0MFlURVUKTUJJR0ExVUVDd3dMVTFOUFVISnZkbWxrWlhJeEZEQVNCZ05WQkFNTUMzTjFZbk53WVdObGMzY3hNUnd3R2dZSktvWklodmNOQVFrQgpGZzFwYm1adlFHOXJkR0V1WTI5dE1CNFhEVEUwTURVeU56QTRNamt5TjFvWERUUTBNRFV5TnpBNE16QXlOMW93Z1pNeEN6QUpCZ05WCkJBWVRBbFZUTVJNd0VRWURWUVFJREFwRFlXeHBabTl5Ym1saE1SWXdGQVlEVlFRSERBMVRZVzRnUm5KaGJtTnBjMk52TVEwd0N3WUQKVlFRS0RBUlBhM1JoTVJRd0VnWURWUVFMREF0VFUwOVFjbTkyYVdSbGNqRVVNQklHQTFVRUF3d0xjM1ZpYzNCaFkyVnpkekV4SERBYQpCZ2txaGtpRzl3MEJDUUVXRFdsdVptOUFiMnQwWVM1amIyMHdnWjh3RFFZSktvWklodmNOQVFFQkJRQURnWTBBTUlHSkFvR0JBS1lYCi9VZFY5SExYYk5LdjB5YzZZSkJ0emRXTnVHVFBJWFdWUENiME9zUnZSNTRscSswU0xQUUdKUzM5ZmxXS2lxdFVpRXVzdWloNkdkTGYKTnZGQVZMR1BxQlRXUTRMYzdyNSt6RDVxbkg2TGlUTTFLQ2JhRjN1dTJQK1QrdXRzR3FGVVphd0E5RkVWTkxrSUNlMzZYMXlFNDBYKwovak15Z3lpZVFQTWVKQUJ2QWdNQkFBRXdEUVlKS29aSWh2Y05BUUVGQlFBRGdZRUFIU1dQRzR5MWJOeUp5U2diRnFEY1MvNk1VTklyClNma1FZSXh6SUdRMzdxeTVxQVcxNVlrQlVpVzlUc0dKUmNyZ3VzVnJaSWlhMThlWXo4NFpuN0Z5VVpOTUZvMjRMN2w2QlMwV0NpdEkKUVNjQkNLQjRRV0EvYjFzenFzN0V0cE9jUFAwMVRZTnEycmFzK1ZxUjNhV0FYTFgyb0tmQ2xWL1NVd3N6UmY1VTg1WT08L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT48c2FtbDI6U3ViamVjdCB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+PHNhbWwyOk5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OmVtYWlsQWRkcmVzcyI+YmVuQHN1YnNwYWNlc3cuY29tPC9zYW1sMjpOYW1lSUQ+PHNhbWwyOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgSW5SZXNwb25zZVRvPSJfNWMzODVhYmIxNzczNWI3YWE4ZDEiIE5vdE9uT3JBZnRlcj0iMjAxNC0wNS0yN1QyMzozMjozNS40MjZaIiBSZWNpcGllbnQ9Imh0dHA6Ly9sb2NhbGhvc3QvYnJvd3NlclNhbWxMb2dpbiIvPjwvc2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbj48L3NhbWwyOlN1YmplY3Q+PHNhbWwyOkNvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDE0LTA1LTI3VDIzOjIyOjM1LjQyNloiIE5vdE9uT3JBZnRlcj0iMjAxNC0wNS0yN1QyMzozMjozNS40MjZaIiB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+PHNhbWwyOkF1ZGllbmNlUmVzdHJpY3Rpb24+PHNhbWwyOkF1ZGllbmNlPmh0dHBzOi8vYWRtaW4uc3Vic3BhY2Vzdy5jb208L3NhbWwyOkF1ZGllbmNlPjwvc2FtbDI6QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWwyOkNvbmRpdGlvbnM+PHNhbWwyOkF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAxNC0wNS0yN1QyMzoyNzozNS40MjZaIiBTZXNzaW9uSW5kZXg9Il81YzM4NWFiYjE3NzM1YjdhYThkMSIgeG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPjxzYW1sMjpBdXRobkNvbnRleHQ+PHNhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlg1MDk8L3NhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbDI6QXV0aG5Db250ZXh0Pjwvc2FtbDI6QXV0aG5TdGF0ZW1lbnQ+PC9zYW1sMjpBc3NlcnRpb24+PC9zYW1sMnA6UmVzcG9uc2U+',
          RelayState: '',
        },
        config: {
          entryPoint: 'https://subspacesw1.okta.com/app/subspacesw_subspacetest_1/kvjj46lsDQEQYUDBZIYW/sso/saml',
          cert: 'MIICoTCCAgqgAwIBAgIGAUY8zVPYMA0GCSqGSIb3DQEBBQUAMIGTMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxFDASBgNVBAMMC3N1YnNwYWNlc3cxMRwwGgYJKoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMB4XDTE0MDUyNzA4MjkyN1oXDTQ0MDUyNzA4MzAyN1owgZMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ0wCwYDVQQKDARPa3RhMRQwEgYDVQQLDAtTU09Qcm92aWRlcjEUMBIGA1UEAwwLc3Vic3BhY2VzdzExHDAaBgkqhkiG9w0BCQEWDWluZm9Ab2t0YS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKYX/UdV9HLXbNKv0yc6YJBtzdWNuGTPIXWVPCb0OsRvR54lq+0SLPQGJS39flWKiqtUiEusuih6GdLfNvFAVLGPqBTWQ4Lc7r5+zD5qnH6LiTM1KCbaF3uu2P+T+utsGqFUZawA9FEVNLkICe36X1yE40X+/jMygyieQPMeJABvAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAHSWPG4y1bNyJySgbFqDcS/6MUNIrSfkQYIxzIGQ37qy5qAW15YkBUiW9TsGJRcrgusVrZIia18eYz84Zn7FyUZNMFo24L7l6BS0WCitIQScBCKB4QWA/b1szqs7EtpOcPP01TYNq2ras+VqR3aWAXLX2oKfClV/SUwszRf5U85Y='
        },
        expectedStatusCode: 200,
        expectedNameIDStartsWith: 'ben'
      },
      { name: 'Onelogin -- invalid cert (from Okta case) should fail',
        samlResponse: {
          SAMLResponse: 'PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0\r\nYzpTQU1MOjIuMDphc3NlcnRpb24iIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6\r\nbmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJSNjg5YjA3MzNiY2Nj\r\nYTIyYTEzN2UzNjU0ODMwMzEyMzMyOTQwYjFiZSIgVmVyc2lvbj0iMi4wIiBJ\r\nc3N1ZUluc3RhbnQ9IjIwMTQtMDUtMjhUMDA6MTY6MDhaIiBEZXN0aW5hdGlv\r\nbj0ie3JlY2lwaWVudH0iIEluUmVzcG9uc2VUbz0iX2E2ZmM0NmJlODRlMWUz\r\nY2YzYzUwIj48c2FtbDpJc3N1ZXI+aHR0cHM6Ly9hcHAub25lbG9naW4uY29t\r\nL3NhbWwvbWV0YWRhdGEvMzcxNzU1PC9zYW1sOklzc3Vlcj48c2FtbHA6U3Rh\r\ndHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6\r\ndGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWxwOlN0YXR1cz48\r\nc2FtbDpBc3NlcnRpb24geG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIw\r\nMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIw\r\nMDEvWE1MU2NoZW1hLWluc3RhbmNlIiBWZXJzaW9uPSIyLjAiIElEPSJwZngz\r\nYjYzYzdiZS1mZTg2LTYyZmQtOGNiNS0xNmFiNjI3M2VmYWEiIElzc3VlSW5z\r\ndGFudD0iMjAxNC0wNS0yOFQwMDoxNjowOFoiPjxzYW1sOklzc3Vlcj5odHRw\r\nczovL2FwcC5vbmVsb2dpbi5jb20vc2FtbC9tZXRhZGF0YS8zNzE3NTU8L3Nh\r\nbWw6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cu\r\ndzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpD\r\nYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53\r\nMy5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PGRzOlNpZ25hdHVyZU1l\r\ndGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1s\r\nZHNpZyNyc2Etc2hhMSIvPjxkczpSZWZlcmVuY2UgVVJJPSIjcGZ4M2I2M2M3\r\nYmUtZmU4Ni02MmZkLThjYjUtMTZhYjYyNzNlZmFhIj48ZHM6VHJhbnNmb3Jt\r\ncz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcv\r\nMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48ZHM6VHJh\r\nbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94\r\nbWwtZXhjLWMxNG4jIi8+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRo\r\nb2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRz\r\naWcjc2hhMSIvPjxkczpEaWdlc3RWYWx1ZT5EQ25QVFFZQmIxaEtzcGJlNmZn\r\nMVUzcTh4bjQ9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2Rz\r\nOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPmUwK2FGb21BMCtKQVkw\r\nZjl0S3F6SXVxSVZTU3c3TGlGVXNuZUVES1BCV2RpVHoxc01kZ3IvMnkxZTkr\r\ncmphUzJtUm1DaS92U1FMWTN6VFl6MGhwNm5KTlUxOStUV29YbzlrSFF5V1Q0\r\nS2tlUUw0WHMvZ1ovQW9LQzIwaUhWS3RwUHBzMElRME1sL3FSb291U2l0dDZT\r\nZi9XRHoyTFYvcFdjSDJoeDV0djN4U3czNmhLMk5RYzdxdzdyMW1FWG52Y2pY\r\nUmVZbzhyclZmN1hIR0d4Tm9SSUVJQ1VJaTExMHV2c1dlbVNYZjBaMGR5YjBG\r\nVllPV3VTc1FNRGx6TnBoZUFEQmlmRk80VVRmU0VoRlp2bjhrVkNHWlVJd3Ji\r\nT2haMmQvK1lFdGd5dVRnK3F0c2xnZnk0ZHdkNFR2RWNmdVJ6UVRhemVlZnBy\r\nU0Z5aVFja0FYT2pjdz09PC9kczpTaWduYXR1cmVWYWx1ZT48ZHM6S2V5SW5m\r\nbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlFRnpDQ0F2\r\nK2dBd0lCQWdJVUZKc1VqUE03QW1Xdk50RXZVTFNIbFRUTWlMUXdEUVlKS29a\r\nSWh2Y05BUUVGQlFBd1dERUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQW9N\r\nQ0ZOMVluTndZV05sTVJVd0V3WURWUVFMREF4UGJtVk1iMmRwYmlCSlpGQXhI\r\nekFkQmdOVkJBTU1Gazl1WlV4dloybHVJRUZqWTI5MWJuUWdOREl6TkRrd0ho\r\nY05NVFF3TlRFek1UZ3dOakV5V2hjTk1Ua3dOVEUwTVRnd05qRXlXakJZTVFz\r\nd0NRWURWUVFHRXdKVlV6RVJNQThHQTFVRUNnd0lVM1ZpYzNCaFkyVXhGVEFU\r\nQmdOVkJBc01ERTl1WlV4dloybHVJRWxrVURFZk1CMEdBMVVFQXd3V1QyNWxU\r\nRzluYVc0Z1FXTmpiM1Z1ZENBME1qTTBPVENDQVNJd0RRWUpLb1pJaHZjTkFR\r\nRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFLckF6SmRZOUZ6Rkx0NWJsQXJKZlB6\r\nZ2k4N0VuRkdsVGZjVjVUMVRVRHdMQmxEa1kvMFpHS25NT3BmM0Q3aWUyQzRw\r\nUEZPSW1Pb2djTTVrcERETDdxeFRYWjFld1hWeWpCZE11MjlORzJDNk56V2VR\r\nVFVNVWppMDFFY0hrQzhvK1B0czhBTmlOT1ljanhFZXloRXl6SktnRWl6YmxZ\r\nek1NS3pkck9FVDZRdXFXbzNDODNLKzUrNWRzakRuMW9vS0dSd2ozSHZnc1lj\r\nRnJRbDlOb2pnUUZqb29id3NpRS83QStPSmhMcEJjeS9uU1Znbm9KYU1mck8r\r\nSnNudWtaUHp0Ym50THZPbDU2K1ZyYTBOOG41TkFZaGFTYXlQaXYvYXloalZn\r\namZYZDF0ak1WVE9pRGtuVU93aXpadUoxWTNRSDk0dlV0QmdwMFdCcEJTcy94\r\nTXlUczhDQXdFQUFhT0IyRENCMVRBTUJnTlZIUk1CQWY4RUFqQUFNQjBHQTFV\r\nZERnUVdCQlJRTzRXcE01Zld3eGliNDlXVHVKa2ZZRGJ4T0RDQmxRWURWUjBq\r\nQklHTk1JR0tnQlJRTzRXcE01Zld3eGliNDlXVHVKa2ZZRGJ4T0tGY3BGb3dX\r\nREVMTUFrR0ExVUVCaE1DVlZNeEVUQVBCZ05WQkFvTUNGTjFZbk53WVdObE1S\r\nVXdFd1lEVlFRTERBeFBibVZNYjJkcGJpQkpaRkF4SHpBZEJnTlZCQU1NRms5\r\ndVpVeHZaMmx1SUVGalkyOTFiblFnTkRJek5EbUNGQlNiRkl6ek93SmxyemJS\r\nTDFDMGg1VTB6SWkwTUE0R0ExVWREd0VCL3dRRUF3SUhnREFOQmdrcWhraUc5\r\ndzBCQVFVRkFBT0NBUUVBQ2REQUFvYVpGQ0VZNXBtZndiS3VLclh0TzVpRThs\r\nV3RpQ1BqQ1pFVXVUNmJYUk5jcXJkbnVWL0VBZlg5V1FvWGphbFBpMGVNNzh6\r\nS21idlJHU1RVSHdXdzQ5UkhqRmZlSlVLdkhOZU5uRmdUWERqRVBOaE12aDY5\r\na0htNDUzbEZSbUIra2s2eWp0WFJaYVFFd1M4VXVvMk90K2tyZ05ibDZvVEJa\r\nSjBBSEgxTXRaRUNEbG9tczFLbTd6c0s4d0FpNWk4VFZJS2tWcjViMlZsaHJM\r\nZ0ZNdnpaNVZpQXhJTUdCNnc0N3lZNFFHUUIvNVE4eWE5aEJzOXZrbit3dWJB\r\nK3lyNGoxNEpYWjdibFZLRFNUWXZhNjVFYStQcUh5cnArV25tbmJ3Mk9iUzdp\r\nV2V4aVR5MWpEM0cwUjJhdkRCRmpNOEZqNURiZnVmc0UxYjBVMTBSVHRnPT08\r\nL2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5m\r\nbz48L2RzOlNpZ25hdHVyZT48c2FtbDpTdWJqZWN0PjxzYW1sOk5hbWVJRCBG\r\nb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9y\r\nbWF0OnRyYW5zaWVudCI+cGxvZXJAc3Vic3BhY2Vzdy5jb208L3NhbWw6TmFt\r\nZUlEPjxzYW1sOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2Fz\r\naXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDpTdWJqZWN0\r\nQ29uZmlybWF0aW9uRGF0YSBOb3RPbk9yQWZ0ZXI9IjIwMTQtMDUtMjhUMDA6\r\nMTk6MDhaIiBSZWNpcGllbnQ9IntyZWNpcGllbnR9IiBJblJlc3BvbnNlVG89\r\nIl9hNmZjNDZiZTg0ZTFlM2NmM2M1MCIvPjwvc2FtbDpTdWJqZWN0Q29uZmly\r\nbWF0aW9uPjwvc2FtbDpTdWJqZWN0PjxzYW1sOkNvbmRpdGlvbnMgTm90QmVm\r\nb3JlPSIyMDE0LTA1LTI4VDAwOjEzOjA4WiIgTm90T25PckFmdGVyPSIyMDE0\r\nLTA1LTI4VDAwOjE5OjA4WiI+PHNhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48\r\nc2FtbDpBdWRpZW5jZT57YXVkaWVuY2V9PC9zYW1sOkF1ZGllbmNlPjwvc2Ft\r\nbDpBdWRpZW5jZVJlc3RyaWN0aW9uPjwvc2FtbDpDb25kaXRpb25zPjxzYW1s\r\nOkF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAxNC0wNS0yOFQwMDox\r\nNjowN1oiIFNlc3Npb25Ob3RPbk9yQWZ0ZXI9IjIwMTQtMDUtMjlUMDA6MTY6\r\nMDhaIiBTZXNzaW9uSW5kZXg9Il8zMGE0YWY1MC1jODJiLTAxMzEtZjhiNS03\r\nODJiY2I1NmZjYWEiPjxzYW1sOkF1dGhuQ29udGV4dD48c2FtbDpBdXRobkNv\r\nbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6\r\nY2xhc3NlczpQYXNzd29yZFByb3RlY3RlZFRyYW5zcG9ydDwvc2FtbDpBdXRo\r\nbkNvbnRleHRDbGFzc1JlZj48L3NhbWw6QXV0aG5Db250ZXh0Pjwvc2FtbDpB\r\ndXRoblN0YXRlbWVudD48L3NhbWw6QXNzZXJ0aW9uPjwvc2FtbHA6UmVzcG9u\r\nc2U+Cgo=\r\n'
        },
        config: {
          entryPoint: 'https://subspacesw1.okta.com/app/subspacesw_subspacetest_1/kvjj46lsDQEQYUDBZIYW/sso/saml',
          cert: 'MIICoTCCAgqgAwIBAgIGAUY8zVPYMA0GCSqGSIb3DQEBBQUAMIGTMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxFDASBgNVBAMMC3N1YnNwYWNlc3cxMRwwGgYJKoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMB4XDTE0MDUyNzA4MjkyN1oXDTQ0MDUyNzA4MzAyN1owgZMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ0wCwYDVQQKDARPa3RhMRQwEgYDVQQLDAtTU09Qcm92aWRlcjEUMBIGA1UEAwwLc3Vic3BhY2VzdzExHDAaBgkqhkiG9w0BCQEWDWluZm9Ab2t0YS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKYX/UdV9HLXbNKv0yc6YJBtzdWNuGTPIXWVPCb0OsRvR54lq+0SLPQGJS39flWKiqtUiEusuih6GdLfNvFAVLGPqBTWQ4Lc7r5+zD5qnH6LiTM1KCbaF3uu2P+T+utsGqFUZawA9FEVNLkICe36X1yE40X+/jMygyieQPMeJABvAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAHSWPG4y1bNyJySgbFqDcS/6MUNIrSfkQYIxzIGQ37qy5qAW15YkBUiW9TsGJRcrgusVrZIia18eYz84Zn7FyUZNMFo24L7l6BS0WCitIQScBCKB4QWA/b1szqs7EtpOcPP01TYNq2ras+VqR3aWAXLX2oKfClV/SUwszRf5U85Y='
        },
        expectedStatusCode: 500
      },
      { name: 'Onelogin -- valid config should succeed',
        samlResponse: {
          SAMLResponse: 'PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0\r\nYzpTQU1MOjIuMDphc3NlcnRpb24iIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6\r\nbmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJSNjg5YjA3MzNiY2Nj\r\nYTIyYTEzN2UzNjU0ODMwMzEyMzMyOTQwYjFiZSIgVmVyc2lvbj0iMi4wIiBJ\r\nc3N1ZUluc3RhbnQ9IjIwMTQtMDUtMjhUMDA6MTY6MDhaIiBEZXN0aW5hdGlv\r\nbj0ie3JlY2lwaWVudH0iIEluUmVzcG9uc2VUbz0iX2E2ZmM0NmJlODRlMWUz\r\nY2YzYzUwIj48c2FtbDpJc3N1ZXI+aHR0cHM6Ly9hcHAub25lbG9naW4uY29t\r\nL3NhbWwvbWV0YWRhdGEvMzcxNzU1PC9zYW1sOklzc3Vlcj48c2FtbHA6U3Rh\r\ndHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6\r\ndGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWxwOlN0YXR1cz48\r\nc2FtbDpBc3NlcnRpb24geG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIw\r\nMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIw\r\nMDEvWE1MU2NoZW1hLWluc3RhbmNlIiBWZXJzaW9uPSIyLjAiIElEPSJwZngz\r\nYjYzYzdiZS1mZTg2LTYyZmQtOGNiNS0xNmFiNjI3M2VmYWEiIElzc3VlSW5z\r\ndGFudD0iMjAxNC0wNS0yOFQwMDoxNjowOFoiPjxzYW1sOklzc3Vlcj5odHRw\r\nczovL2FwcC5vbmVsb2dpbi5jb20vc2FtbC9tZXRhZGF0YS8zNzE3NTU8L3Nh\r\nbWw6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cu\r\ndzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpD\r\nYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53\r\nMy5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PGRzOlNpZ25hdHVyZU1l\r\ndGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1s\r\nZHNpZyNyc2Etc2hhMSIvPjxkczpSZWZlcmVuY2UgVVJJPSIjcGZ4M2I2M2M3\r\nYmUtZmU4Ni02MmZkLThjYjUtMTZhYjYyNzNlZmFhIj48ZHM6VHJhbnNmb3Jt\r\ncz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcv\r\nMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48ZHM6VHJh\r\nbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94\r\nbWwtZXhjLWMxNG4jIi8+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRo\r\nb2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRz\r\naWcjc2hhMSIvPjxkczpEaWdlc3RWYWx1ZT5EQ25QVFFZQmIxaEtzcGJlNmZn\r\nMVUzcTh4bjQ9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2Rz\r\nOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPmUwK2FGb21BMCtKQVkw\r\nZjl0S3F6SXVxSVZTU3c3TGlGVXNuZUVES1BCV2RpVHoxc01kZ3IvMnkxZTkr\r\ncmphUzJtUm1DaS92U1FMWTN6VFl6MGhwNm5KTlUxOStUV29YbzlrSFF5V1Q0\r\nS2tlUUw0WHMvZ1ovQW9LQzIwaUhWS3RwUHBzMElRME1sL3FSb291U2l0dDZT\r\nZi9XRHoyTFYvcFdjSDJoeDV0djN4U3czNmhLMk5RYzdxdzdyMW1FWG52Y2pY\r\nUmVZbzhyclZmN1hIR0d4Tm9SSUVJQ1VJaTExMHV2c1dlbVNYZjBaMGR5YjBG\r\nVllPV3VTc1FNRGx6TnBoZUFEQmlmRk80VVRmU0VoRlp2bjhrVkNHWlVJd3Ji\r\nT2haMmQvK1lFdGd5dVRnK3F0c2xnZnk0ZHdkNFR2RWNmdVJ6UVRhemVlZnBy\r\nU0Z5aVFja0FYT2pjdz09PC9kczpTaWduYXR1cmVWYWx1ZT48ZHM6S2V5SW5m\r\nbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlFRnpDQ0F2\r\nK2dBd0lCQWdJVUZKc1VqUE03QW1Xdk50RXZVTFNIbFRUTWlMUXdEUVlKS29a\r\nSWh2Y05BUUVGQlFBd1dERUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQW9N\r\nQ0ZOMVluTndZV05sTVJVd0V3WURWUVFMREF4UGJtVk1iMmRwYmlCSlpGQXhI\r\nekFkQmdOVkJBTU1Gazl1WlV4dloybHVJRUZqWTI5MWJuUWdOREl6TkRrd0ho\r\nY05NVFF3TlRFek1UZ3dOakV5V2hjTk1Ua3dOVEUwTVRnd05qRXlXakJZTVFz\r\nd0NRWURWUVFHRXdKVlV6RVJNQThHQTFVRUNnd0lVM1ZpYzNCaFkyVXhGVEFU\r\nQmdOVkJBc01ERTl1WlV4dloybHVJRWxrVURFZk1CMEdBMVVFQXd3V1QyNWxU\r\nRzluYVc0Z1FXTmpiM1Z1ZENBME1qTTBPVENDQVNJd0RRWUpLb1pJaHZjTkFR\r\nRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFLckF6SmRZOUZ6Rkx0NWJsQXJKZlB6\r\nZ2k4N0VuRkdsVGZjVjVUMVRVRHdMQmxEa1kvMFpHS25NT3BmM0Q3aWUyQzRw\r\nUEZPSW1Pb2djTTVrcERETDdxeFRYWjFld1hWeWpCZE11MjlORzJDNk56V2VR\r\nVFVNVWppMDFFY0hrQzhvK1B0czhBTmlOT1ljanhFZXloRXl6SktnRWl6YmxZ\r\nek1NS3pkck9FVDZRdXFXbzNDODNLKzUrNWRzakRuMW9vS0dSd2ozSHZnc1lj\r\nRnJRbDlOb2pnUUZqb29id3NpRS83QStPSmhMcEJjeS9uU1Znbm9KYU1mck8r\r\nSnNudWtaUHp0Ym50THZPbDU2K1ZyYTBOOG41TkFZaGFTYXlQaXYvYXloalZn\r\namZYZDF0ak1WVE9pRGtuVU93aXpadUoxWTNRSDk0dlV0QmdwMFdCcEJTcy94\r\nTXlUczhDQXdFQUFhT0IyRENCMVRBTUJnTlZIUk1CQWY4RUFqQUFNQjBHQTFV\r\nZERnUVdCQlJRTzRXcE01Zld3eGliNDlXVHVKa2ZZRGJ4T0RDQmxRWURWUjBq\r\nQklHTk1JR0tnQlJRTzRXcE01Zld3eGliNDlXVHVKa2ZZRGJ4T0tGY3BGb3dX\r\nREVMTUFrR0ExVUVCaE1DVlZNeEVUQVBCZ05WQkFvTUNGTjFZbk53WVdObE1S\r\nVXdFd1lEVlFRTERBeFBibVZNYjJkcGJpQkpaRkF4SHpBZEJnTlZCQU1NRms5\r\ndVpVeHZaMmx1SUVGalkyOTFiblFnTkRJek5EbUNGQlNiRkl6ek93SmxyemJS\r\nTDFDMGg1VTB6SWkwTUE0R0ExVWREd0VCL3dRRUF3SUhnREFOQmdrcWhraUc5\r\ndzBCQVFVRkFBT0NBUUVBQ2REQUFvYVpGQ0VZNXBtZndiS3VLclh0TzVpRThs\r\nV3RpQ1BqQ1pFVXVUNmJYUk5jcXJkbnVWL0VBZlg5V1FvWGphbFBpMGVNNzh6\r\nS21idlJHU1RVSHdXdzQ5UkhqRmZlSlVLdkhOZU5uRmdUWERqRVBOaE12aDY5\r\na0htNDUzbEZSbUIra2s2eWp0WFJaYVFFd1M4VXVvMk90K2tyZ05ibDZvVEJa\r\nSjBBSEgxTXRaRUNEbG9tczFLbTd6c0s4d0FpNWk4VFZJS2tWcjViMlZsaHJM\r\nZ0ZNdnpaNVZpQXhJTUdCNnc0N3lZNFFHUUIvNVE4eWE5aEJzOXZrbit3dWJB\r\nK3lyNGoxNEpYWjdibFZLRFNUWXZhNjVFYStQcUh5cnArV25tbmJ3Mk9iUzdp\r\nV2V4aVR5MWpEM0cwUjJhdkRCRmpNOEZqNURiZnVmc0UxYjBVMTBSVHRnPT08\r\nL2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5m\r\nbz48L2RzOlNpZ25hdHVyZT48c2FtbDpTdWJqZWN0PjxzYW1sOk5hbWVJRCBG\r\nb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9y\r\nbWF0OnRyYW5zaWVudCI+cGxvZXJAc3Vic3BhY2Vzdy5jb208L3NhbWw6TmFt\r\nZUlEPjxzYW1sOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2Fz\r\naXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDpTdWJqZWN0\r\nQ29uZmlybWF0aW9uRGF0YSBOb3RPbk9yQWZ0ZXI9IjIwMTQtMDUtMjhUMDA6\r\nMTk6MDhaIiBSZWNpcGllbnQ9IntyZWNpcGllbnR9IiBJblJlc3BvbnNlVG89\r\nIl9hNmZjNDZiZTg0ZTFlM2NmM2M1MCIvPjwvc2FtbDpTdWJqZWN0Q29uZmly\r\nbWF0aW9uPjwvc2FtbDpTdWJqZWN0PjxzYW1sOkNvbmRpdGlvbnMgTm90QmVm\r\nb3JlPSIyMDE0LTA1LTI4VDAwOjEzOjA4WiIgTm90T25PckFmdGVyPSIyMDE0\r\nLTA1LTI4VDAwOjE5OjA4WiI+PHNhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48\r\nc2FtbDpBdWRpZW5jZT57YXVkaWVuY2V9PC9zYW1sOkF1ZGllbmNlPjwvc2Ft\r\nbDpBdWRpZW5jZVJlc3RyaWN0aW9uPjwvc2FtbDpDb25kaXRpb25zPjxzYW1s\r\nOkF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAxNC0wNS0yOFQwMDox\r\nNjowN1oiIFNlc3Npb25Ob3RPbk9yQWZ0ZXI9IjIwMTQtMDUtMjlUMDA6MTY6\r\nMDhaIiBTZXNzaW9uSW5kZXg9Il8zMGE0YWY1MC1jODJiLTAxMzEtZjhiNS03\r\nODJiY2I1NmZjYWEiPjxzYW1sOkF1dGhuQ29udGV4dD48c2FtbDpBdXRobkNv\r\nbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6\r\nY2xhc3NlczpQYXNzd29yZFByb3RlY3RlZFRyYW5zcG9ydDwvc2FtbDpBdXRo\r\nbkNvbnRleHRDbGFzc1JlZj48L3NhbWw6QXV0aG5Db250ZXh0Pjwvc2FtbDpB\r\ndXRoblN0YXRlbWVudD48L3NhbWw6QXNzZXJ0aW9uPjwvc2FtbHA6UmVzcG9u\r\nc2U+Cgo=\r\n'
        },
        config: {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
          cert: 'MIIEFzCCAv+gAwIBAgIUFJsUjPM7AmWvNtEvULSHlTTMiLQwDQYJKoZIhvcNAQEFBQAwWDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFN1YnNwYWNlMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgNDIzNDkwHhcNMTQwNTEzMTgwNjEyWhcNMTkwNTE0MTgwNjEyWjBYMQswCQYDVQQGEwJVUzERMA8GA1UECgwIU3Vic3BhY2UxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwWT25lTG9naW4gQWNjb3VudCA0MjM0OTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKrAzJdY9FzFLt5blArJfPzgi87EnFGlTfcV5T1TUDwLBlDkY/0ZGKnMOpf3D7ie2C4pPFOImOogcM5kpDDL7qxTXZ1ewXVyjBdMu29NG2C6NzWeQTUMUji01EcHkC8o+Pts8ANiNOYcjxEeyhEyzJKgEizblYzMMKzdrOET6QuqWo3C83K+5+5dsjDn1ooKGRwj3HvgsYcFrQl9NojgQFjoobwsiE/7A+OJhLpBcy/nSVgnoJaMfrO+JsnukZPztbntLvOl56+Vra0N8n5NAYhaSayPiv/ayhjVgjfXd1tjMVTOiDknUOwizZuJ1Y3QH94vUtBgp0WBpBSs/xMyTs8CAwEAAaOB2DCB1TAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRQO4WpM5fWwxib49WTuJkfYDbxODCBlQYDVR0jBIGNMIGKgBRQO4WpM5fWwxib49WTuJkfYDbxOKFcpFowWDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFN1YnNwYWNlMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgNDIzNDmCFBSbFIzzOwJlrzbRL1C0h5U0zIi0MA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEACdDAAoaZFCEY5pmfwbKuKrXtO5iE8lWtiCPjCZEUuT6bXRNcqrdnuV/EAfX9WQoXjalPi0eM78zKmbvRGSTUHwWw49RHjFfeJUKvHNeNnFgTXDjEPNhMvh69kHm453lFRmB+kk6yjtXRZaQEwS8Uuo2Ot+krgNbl6oTBZJ0AHH1MtZECDloms1Km7zsK8wAi5i8TVIKkVr5b2VlhrLgFMvzZ5ViAxIMGB6w47yY4QGQB/5Q8ya9hBs9vkn+wubA+yr4j14JXZ7blVKDSTYva65Ea+PqHyrp+Wnmnbw2ObS7iWexiTy1jD3G0R2avDBFjM8Fj5DbfufsE1b0U10RTtg=='
        },
        expectedStatusCode: 200,
        expectedNameIDStartsWith: 'ploer'
      },
    ];

    var server;

    function testForCheck( check ) {
      return function( done ) {
        var app = express();
        app.use( bodyParser.urlencoded() );
        app.use( passport.initialize() );
        var config = check.config;
        config.callbackUrl = 'http://localhost:3033/login';
        var profile = null;
        passport.use( new SamlStrategy( config, function(_profile, done) {
            profile = _profile;
            done(null, { id: profile.nameID } );
          })
        );

        app.post( '/login', 
          passport.authenticate( "saml", { session: false } ),
          function(req, res) {
            res.send( 200, "200 OK" );
          });

        app.use( function( err, req, res, next ) {
          //console.log( err.stack );
          res.send( 500, '500 Internal Server Error' );
        });

        server = app.listen( 3033, function() {
          var requestOpts = {
            url: 'http://localhost:3033/login',
            method: 'POST',
            form: check.samlResponse
          };

          request(requestOpts, function(err, response, body) {
            should.not.exist(err);
            response.statusCode.should.equal(check.expectedStatusCode);
            if (response.statusCode == 200)
              profile.nameID.should.startWith(check.expectedNameIDStartsWith);
            done();
          });
        });
      };
    }

    for( var i = 0; i < capturedChecks.length; i++ ) {
      var check = capturedChecks[i];
      it( check.name, testForCheck( check ) );
    }

    afterEach( function( done ) {
      server.close( done );
    });
  });

  describe( 'captured SAML requests /', function() {
    var capturedChecks = [
      { name: "Empty Config",
        config: {},
        result: {
          'samlp:AuthnRequest': 
           { '$': 
              { 'xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
                Version: '2.0',
                ProtocolBinding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                AssertionConsumerServiceURL: 'http://localhost:3033/login',
                Destination: 'https://wwwexampleIdp.com/saml' },
             'saml:Issuer': 
              [ { _: 'onelogin_saml',
                  '$': { 'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion' } } ],
             'samlp:NameIDPolicy': 
              [ { '$': 
                   { 'xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
                     Format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
                     AllowCreate: 'true' } } ],
             'samlp:RequestedAuthnContext': 
              [ { '$': 
                   { 'xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
                     Comparison: 'exact' },
                  'saml:AuthnContextClassRef': 
                   [ { _: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
                       '$': { 'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion' } } ] } ] } }
      },
    { name: "Config #2",
        config: {
          issuer: 'http://exampleSp.com/saml',
          identifierFormat: 'alternateIdentifier',
          passive: true
        },
        result: { 
          'samlp:AuthnRequest': 
           { '$': 
              { 'xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
                Version: '2.0',
                ProtocolBinding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                AssertionConsumerServiceURL: 'http://localhost:3033/login',
                Destination: 'https://wwwexampleIdp.com/saml',
                IsPassive: 'true' },
             'saml:Issuer': 
              [ { _: 'http://exampleSp.com/saml',
                  '$': { 'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion' } } ],
             'samlp:NameIDPolicy': 
              [ { '$': 
                   { 'xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
                     Format: 'alternateIdentifier',
                     AllowCreate: 'true' } } ],
             'samlp:RequestedAuthnContext': 
              [ { '$': 
                   { 'xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
                     Comparison: 'exact' },
                  'saml:AuthnContextClassRef': 
                   [ { _: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
                       '$': { 'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion' } } ] } ] } }
      }
    ];

    var server;

    function testForCheck( check ) {
      return function( done ) {
        var app = express();
        app.use( bodyParser.urlencoded() );
        app.use( passport.initialize() );
        var config = check.config;
        config.callbackUrl = 'http://localhost:3033/login';
        config.entryPoint = 'https://wwwexampleIdp.com/saml';
        var profile = null;
        passport.use( new SamlStrategy( config, function(_profile, done) {
            profile = _profile;
            done(null, { id: profile.nameID } );
          })
        );

        app.get( '/login', 
          passport.authenticate( "saml", { samlFallback: 'login-request', session: false } ),
          function(req, res) {
            res.send( 200, "200 OK" );
          });

        app.use( function( err, req, res, next ) {
          //console.log( err.stack );
          res.send( 500, '500 Internal Server Error' );
        });

        server = app.listen( 3033, function() {
          var requestOpts = {
            url: 'http://localhost:3033/login',
            method: 'get',
            followRedirect: false
          };

          request(requestOpts, function(err, response, body) {
            should.not.exist(err);
            response.statusCode.should.equal(302);
            var query = response.headers.location.match( /^[^\?]*\?(.*)$/ )[1];
            var encodedSamlRequest = querystring.parse( query ).SAMLRequest;
            var buffer = new Buffer(encodedSamlRequest, 'base64')
            zlib.inflateRaw( buffer, function(err, samlRequest) {
              should.not.exist( err );
              parseString( samlRequest.toString(), function( err, doc ) {
                should.not.exist( err );
                delete doc['samlp:AuthnRequest']['$']["ID"];
                delete doc['samlp:AuthnRequest']['$']["IssueInstant"];
                doc.should.eql( check.result );
                done();
              });
            });
          });
        });
      };
    }

    for( var i = 0; i < capturedChecks.length; i++ ) {
      var check = capturedChecks[i];
      it( check.name, testForCheck( check ) );
    }

    afterEach( function( done ) {
      server.close( done );
    });
  });

  describe( 'saml.js / ', function() {
    it( 'generateLogoutRequest', function( done ) {
      var expectedRequest = { 
        'samlp:LogoutRequest': 
         { '$': 
            { 'xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
              'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
              //ID: '_85ba0a112df1ffb57805',
              Version: '2.0',
              //IssueInstant: '2014-05-29T03:32:23Z',
              Destination: 'foo' },
           'saml:Issuer': 
            [ { _: 'onelogin_saml',
                '$': { 'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion' } } ],
           'saml:NameID': [ { _: 'bar', '$': { Format: 'foo' } } ] } };

      var samlObj = new SAML( { entryPoint: "foo" } );
      var logoutRequest = samlObj.generateLogoutRequest({
        user: {
          nameIDFormat: 'foo',
          nameID: 'bar'
        }
      });
      parseString( logoutRequest, function( err, doc ) {
        delete doc['samlp:LogoutRequest']['$']["ID"];
        delete doc['samlp:LogoutRequest']['$']["IssueInstant"];
        doc.should.eql( expectedRequest );
        done();
      });
    });

    it( 'generateLogoutResponse', function( done ) {
      var expectedResponse =  { 
        'samlp:LogoutResponse': 
         { '$': 
            { 'xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
              'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
              //ID: '_d11b3c5e085b2417f4aa',
              Version: '2.0',
              //IssueInstant: '2014-05-29T01:11:32Z',
              InResponseTo: 'quux' },
           'saml:Issuer': [ 'onelogin_saml' ],
           'samlp:Status': [ { 'samlp:StatusCode': [ { '$': { Value: 'urn:oasis:names:tc:SAML:2.0:status:Success' } } ] } ] } };

      var samlObj = new SAML( {} );
      var logoutRequest = samlObj.generateLogoutResponse({}, { ID: "quux" });
      parseString( logoutRequest, function( err, doc ) {
        delete doc['samlp:LogoutResponse']['$']["ID"];
        delete doc['samlp:LogoutResponse']['$']["IssueInstant"];
        doc.should.eql( expectedResponse );
        done();
      });
    });
  });
});
