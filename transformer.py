from burp import IBurpExtender
from burp import IHttpListener

import base64
import binascii
import json
import random
import re
import urllib
import uuid


transformations = {
    # encoders
    'b64': lambda params, data: base64.b64encode(data),
    'hex': lambda params, data: binascii.hexlify(data),
    'json': lambda params, data: json.dumps(data)[1:-1],
    'jwt': lambda params, data: base64.urlsafe_b64encode(data).replace(b'=', b''),
    'url': lambda params, data: urllib.quote(data),

    # data generators
    'long': lambda params, data: 'a' * int(params[0]),
    'random': lambda params, data: str(random.randint(int(params[0]), int(params[1]))),
    'uuid': lambda params, data: str(uuid.uuid4()),
}


class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName('Transformer v0.1')
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, tool_flag, message_is_request, message_info):
        if not message_is_request:
            return
        request_info = self._helpers.analyzeRequest(message_info)
        request_raw = self._helpers.bytesToString(message_info.getRequest())
        headers, headers_changed = self._transform(request_raw[0:request_info.getBodyOffset()])
        body, body_changed = self._transform(request_raw[request_info.getBodyOffset():])
        if body_changed:
            headers = re.sub(r'content-length:\s*\d+', 'Content-Length: %d' % len(body), headers, flags=re.IGNORECASE)
        if headers_changed or body_changed:
            message_info.setRequest(self._helpers.stringToBytes(headers + body))

    def _transform(self, data):
        matches = re.finditer(r'{tr:(.+?)}(.*?){tr}', data, flags=re.DOTALL)
        transformed_data = ''
        prev_end = 0
        changed = False
        for match in matches:
            transformed_data_chunk = match.group(2)
            for transformation_call in self._parse_transformation_calls(match.group(1)):
                transformed_data_chunk = transformation_call['transformation'](
                    transformation_call['params'], transformed_data_chunk
                )
            transformed_data += data[prev_end:match.start()] + transformed_data_chunk
            prev_end = match.end()
            changed = True
        transformed_data += data[prev_end:]
        return transformed_data, changed

    @staticmethod
    def _parse_transformation_calls(data):
        global transformations
        transformation_calls = []
        for transformation_call in data.strip().split('&'):
            matches = re.match(r'(.+?)\((.*?)\)', transformation_call.strip())
            if matches:
                transformation = matches.group(1).strip()
                params = matches.group(2).strip()
                if transformation in transformations:
                    transformation_calls.append({
                        'transformation': transformations[transformation],
                        'params': [param.strip() for param in params.split(',')]
                    })
        return transformation_calls
