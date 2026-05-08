from pathlib import Path
for fp in ['/mnt/data/wsroute/frontend.js','/mnt/data/wsroute/template.html']:
    p=Path(fp); s=p.read_text()
    # Insert helpers before deepLinkFromSearch
    marker='function deepLinkFromSearch(){'
    helpers='''function workspaceSlugFromUser(u){
  try{return (u&&(u.workspace_slug||u.workspace_name||u.workspace_id_from_me||u.workspace_id)||'workspace').toString().toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'')||'workspace';}catch(e){return 'workspace';}
}
function workspaceBasePath(u){return '/'+workspaceSlugFromUser(u)+'/';}
function pathParts(){try{return window.location.pathname.split('/').filter(Boolean);}catch(e){return [];}}
function routeViewFromPath(validViews){
  try{
    const parts=pathParts();
    if(!parts.length)return '';
    if(validViews.includes(parts[0]))return parts[0];
    if(parts.length>=2&&validViews.includes(parts[1]))return parts[1];
  }catch(e){}
  return '';
}
function projectIdFromPath(){
  try{
    const parts=pathParts();
    if(parts[0]==='projects'&&parts[1])return parts[1];
    if(parts.length>=3&&parts[1]==='projects')return parts[2];
  }catch(e){}
  return '';
}
'''
    if marker in s and 'function workspaceBasePath' not in s:
        s=s.replace(marker,helpers+'\n'+marker)
    # Set initial path parse/title
    s=s.replace("""      const p=window.location.pathname;\n      const dl=deepLinkFromSearch();""","""      const p=window.location.pathname;\n      const dl=deepLinkFromSearch();""")
    s=s.replace("""      if(p.startsWith('/projects/')&&p.length>10){\n        const pid=p.split('/')[2];\n        if(pid)setInitialProjectId(pid);\n        setView('projects');\n      }""","""      const pid=projectIdFromPath();\n      if(pid){setInitialProjectId(pid);setView('projects');}""")
    s=s.replace("""      const p=window.location.pathname.replace(/^\\//, '').split('/')[0].trim();\n      const VIEW_T={dashboard:'Dashboard',projects:'Projects',tasks:'Kanban Board',messages:'Channels',dm:'Direct Messages',tickets:'Tickets',timeline:'Timeline Tracker',reminders:'Reminders',settings:'Settings',team:'Team Management',productivity:'Dev Productivity'};\n      if(p&&VIEW_T[p]) document.title='Project Tracker — '+VIEW_T[p]+' | AI-Powered Team Collaboration';""","""      const VIEW_T={dashboard:'Dashboard',projects:'Projects',tasks:'Kanban Board',messages:'Channels',dm:'Direct Messages',tickets:'Tickets',timeline:'Timeline Tracker',reminders:'Reminders',settings:'Settings',team:'Team Management',productivity:'Dev Productivity'};\n      const p=routeViewFromPath(Object.keys(VIEW_T));\n      if(p&&VIEW_T[p]) document.title='Project Tracker — '+VIEW_T[p]+' | AI-Powered Team Collaboration';""")
    s=s.replace("""      const p=window.location.pathname.replace(/^\\//, '').split('/')[0].trim();\n      if(p&&VALID_VIEWS.includes(p)) return p;""","""      const p=routeViewFromPath(VALID_VIEWS);\n      if(p&&VALID_VIEWS.includes(p)) return p;""")
    # URL sync push state
    s=s.replace("history.pushState(null,'','/'+base);","history.pushState(null,'',workspaceBasePath(cu)+base);")
    # popstate parse
    s=s.replace("""        const p=window.location.pathname.replace(/^\\//, '').split('/')[0].trim();\n        if(p&&VALID_VIEWS.includes(p)) setView(p);""","""        const p=routeViewFromPath(VALID_VIEWS);\n        if(p&&VALID_VIEWS.includes(p)) setView(p);""")
    # replace task/ticket urls
    s=s.replace("history.replaceState(null,'','/tasks');","history.replaceState(null,'',workspaceBasePath(cu)+'tasks');")
    s=s.replace("history.replaceState(null,'','/tickets');","history.replaceState(null,'',workspaceBasePath(cu)+'tickets');")
    # project detail URLs
    s=s.replace("history.pushState(null,'','/projects/'+slug);","history.pushState(null,'',workspaceBasePath(cu)+'projects/'+slug);")
    s=s.replace("window.location.pathname.startsWith('/projects/')","routeViewFromPath(['projects'])==='projects'")
    s=s.replace("history.pushState(null,'','/projects');","history.pushState(null,'',workspaceBasePath(cu)+'projects');")
    # google auth redirect root
    s=s.replace("history.replaceState(null,'','/');onLogin(u);","history.replaceState(null,'',workspaceBasePath(u));onLogin(u);")
    p.write_text(s)
