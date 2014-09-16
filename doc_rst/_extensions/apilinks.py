'''
Sphinx/docutils extension to create links to pyDoctor documentation using
a RestructuredText interpreted text role that looks like this:

    :api:`python_object_to_link_to <label>`

for example:

    :api:`twisted.internet.defer.Deferred <Deferred>`
'''



def make_api_link(name, rawtext, text, lineno, inliner,
                     options={}, content=[]):

    from docutils import nodes, utils

    # quick, dirty, and ugly...
    if '<' in text and '>' in text:
        full_name, label = text.split('<')
        full_name = full_name.strip()
        label = label.strip('>').strip()
    else:
        full_name = text

    #get the base url for api links from the config file
    env = inliner.document.settings.env
    base_url =  env.config.apilinks_base_url

    # if the first letter of the last element of the link is lowercase
    # we assume the link points to a method
    segs = full_name.split('.')
    isMethod = segs[-1][0].islower()
    if isMethod:
        # http://www.yyy.zz/api/modulename.ClassName-class.html#methodName
        full_name = '%s-class.html#%s'%('.'.join(segs[:-1]), segs[-1])
    else:
        # http://www.yyy.zz/api/modulename.ClassName-class.html
        full_name += '-class.html'
    
    # not really sufficient, but just testing...
    # ...hmmm, maybe this is good enough after all
    ref = base_url + full_name

    node = nodes.reference(rawtext, utils.unescape(label), refuri=ref,
                           **options)

    nodes = [node]
    sys_msgs = []
    return nodes, sys_msgs


# setup function to register the extension

def setup(app):
    app.add_config_value('apilinks_base_url', 
                         'http://foolscap.lothar.com/docs/api/', 
                         'env')
    app.add_role('api', make_api_link)