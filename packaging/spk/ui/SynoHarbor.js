Ext.ns("SYNO.SDS.SynoHarbor");
Ext.define("com.lefterry.synoharbor",{extend:"SYNO.SDS.AppInstance",appWindowName:"SYNO.SDS.SynoHarbor.MainWindow"});
Ext.define("SYNO.SDS.SynoHarbor.MainWindow",{
 extend:"SYNO.SDS.AppWindow",
 constructor:function(config){this.callParent([Ext.apply({title:"SynoHarbor",width:1180,height:800,minWidth:760,minHeight:580,resizable:true,maximizable:true,layout:"fit",items:[new Ext.Panel({border:false,html:'<iframe title="SynoHarbor" src="/webman/3rdparty/synoharbor/index.html" style="border:0;width:100%;height:100%;display:block"></iframe>'})]},config)])}
});
