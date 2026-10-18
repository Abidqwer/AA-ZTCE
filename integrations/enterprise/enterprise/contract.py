"""OpenAPI extension for explicitly scoped desired-state workflow management."""
def extend(document):
    document['info']['version']='0.4.0'
    scope={'type':'array','minItems':1,'maxItems':32,'uniqueItems':True,
           'items':{'type':'string','minLength':1,'maxLength':128}}
    definition={'agents':scope,'resources':scope,'destinations':scope,
                'purpose':{'type':'string','minLength':1,'maxLength':256}}
    schemas=document['components']['schemas']
    schemas['WorkflowWrite']={'type':'object','additionalProperties':False,
        'required':list(definition)+['expected_revision'],
        'properties':{**definition,'expected_revision':{'type':'integer','minimum':0}}}
    schemas['WorkflowRead']={'type':'object','required':['id','revision',*definition],
        'properties':{**definition,'id':{'type':'string'},'revision':{'type':'integer','minimum':1}}}
    schemas['WorkflowDelete']={'type':'object','additionalProperties':False,
        'required':['expected_revision'],'properties':{'expected_revision':{'type':'integer','minimum':0}}}
    errors={str(code):{'description':description} for code,description in
        [(400,'Invalid or reserved workflow'),(401,'Authentication failed'),(403,'Role or target scope denied'),
         (404,'Workflow not found'),(409,'Replay or stale revision'),(413,'Body too large'),(503,'Audit or operation unavailable')]}
    operations={}
    for method,summary in [('get','Read managed workflow'),('put','Create or update a workflow using expected_revision'),('delete','Delete workflow and revoke its sessions')]:
        operation={'summary':summary,'description':'Requires manage_workflows action and agent scope; writes additionally require explicit resource and destination scopes. No identity enrollment or grant issuance.',
            'responses':{'200':{'description':'Desired state returned or deletion applied',
                'content':{'application/json':{'schema':{'$ref':'#/components/schemas/WorkflowRead'}}}} if method!='delete' else
                {'description':'Workflow deleted','content':{'application/json':{'schema':{'type':'object','required':['id','deleted'],
                    'properties':{'id':{'type':'string'},'deleted':{'const':True}}}}}},**errors}}
        if method!='get':operation['requestBody']={'required':True,'content':{'application/json':{
            'schema':{'$ref':'#/components/schemas/'+('WorkflowWrite' if method=='put' else 'WorkflowDelete')}}}}
        operations[method]=operation
    document['paths']['/v1/workflows/{name}']={'parameters':[{'name':'name','in':'path','required':True,
        'schema':{'type':'string','pattern':'^[a-z][a-z0-9_-]{0,63}$'}}],**operations}
    return document
