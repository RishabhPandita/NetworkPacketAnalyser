import java.util.*;
import jpcap.*;
import jpcap.packet.*;
import java.io.*;
import javax.swing.JFrame;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PiePlot3D;
import org.jfree.data.general.DefaultPieDataset;
import org.jfree.data.general.PieDataset;
import org.jfree.util.Rotation;

import java.lang.*;


class PacketPrinter extends JFrame implements PacketReceiver  {
 int pno =0;
 static int tcpcnt;
 static int httpcnt;
 private static final long serialVersionUID = 1L;
 public void receivePacket(Packet packet){
 
     System.out.println("NO "+pno+ "  "+packet);
     pno++;
    }


public static void main(String[] args) throws Exception {

DataInputStream dis = new DataInputStream(System.in);
int ch,ch1,pno=0;
do
{
    System.out.println("1.PACKET SUMMARY\n ");
    System.out.println("2.SELECTED PACKET INFORMATION\n ");
    System.out.println("3.ANALYSIS\n");
    System.out.println("4.Exit\n ");
    System.out.println("\nENTER YOUR CHOICE");
    ch =Integer.parseInt(dis.readLine()) ;
    switch (ch)
         {
            case 1: JpcapCaptor jpcap2 = JpcapCaptor.openFile("C:\\tcp-ecn-sample.pcap");
                    System.out.println("PACKET SUMMARY \n");
                    jpcap2.loopPacket(-1, new PacketPrinter());
                    break;

            case 2: 
                    System.out.println("ENTER PACKET NO. ");
                    pno =  Integer.parseInt(dis.readLine()) ;
                    System.out.println("pno is  " + pno);
                    do
                    {
                        System.out.println("1.PACKET INFORMATION\n ");
                        System.out.println("2.ETHERNET INFORMATION\n ");
                        System.out.println("3.IP INFORMATION\n ");
                        System.out.println("4.TCP INFORMATION\n ");
                        System.out.println("5.HTTP INFORMATION\n ");
                        System.out.println("6.BACK\n ");
                        System.out.println("\nENTER YOUR CHOICE");
                        ch1 =Integer.parseInt(dis.readLine()) ;
                        JpcapCaptor jpcap = JpcapCaptor.openFile("C:\\tcp-ecn-sample.pcap");
                        switch(ch1)
                        {
                            case 1:print(jpcap,1,pno);break;
                            case 2:print(jpcap,2,pno);break;
                            case 3:print(jpcap,3,pno);break;
                            case 4:print(jpcap,4,pno);break;
                            case 5:print(jpcap,5,pno);break;
                            case 6:break;
                            default:System.out.println("\nWRONG CHOICE");
                        }
                    }while(ch1<6);
                    break;

            case 3:
                    do
                    {
                        System.out.println("\n1.PROTOCOL PIE-CHART\n ");
                        System.out.println("2.SOURCE PACKET DISTRIBUTION\n ");
                        System.out.println("3.DESTINATION PACKET DISTRIBUTION\n ");
                        System.out.println("4.AVERAGE CAPTURED PACKET LENGTH\n ");
                        System.out.println("5.DURATION OF TRANSMISSION\n ");
                        System.out.println("6.BACK\n ");
                        System.out.println("\nENTER YOUR CHOICE");
                        ch1 =Integer.parseInt(dis.readLine()) ;
//                        JpcapCaptor jpcap = JpcapCaptor.openFile("C:\\tcp-ecn-sample.pcap");
                        switch(ch1)
                        {
                            case 1:getpiechart1();
                                   PacketPrinter demo1 = new PacketPrinter("PACKET DISTRIBUTION", "TCP AND OTHERS",1);
                                   demo1.pack();
                                   demo1.setVisible(true);

                                    break;
                      
                            case 2:  getpiechart2();
                                     PacketPrinter demo2 = new PacketPrinter("SOURCE PACKET DISTRIBUTION ", " ",2);
                                     demo2.pack();
                                     demo2.setVisible(true);

                            case 3:getpiechart2();
                                   PacketPrinter demo3 = new PacketPrinter("DESTINATION PACKET DISTRIBUTION ", " ",2);
                                   demo3.pack();
                                   demo3.setVisible(true);

                            case 4:getpiechart1();
                                    System.out.print("AVERAGE PACKET LENGTH "+avgpkglen);
                                    break;

                            case 5:gettime();
                                   break;

                            case 6:break;

                            default:System.out.println("WROMG CHOICE");

                        }

                    }while(ch1!=6);
                    break;

            
            case 4:  System.exit(0);

            default: System.out.println("INVALID CHOICE");

         }
}while(ch!=4);
}//main

   static long start;
   static long end;
   static long diff;

   static Date startdate;
   static Date enddate;
   static Date diffdate;

   static int starthours,startmins,startsecs;
   static int endhours,endmins,endsecs;
   
   public static void gettime()throws Exception
   {
       int i=0;
        JpcapCaptor jpcap_1 = JpcapCaptor.openFile("C:\\tcp-ecn-sample.pcap");
        Packet pk=jpcap_1.getPacket();
        start = pk.sec*1000 + pk.usec/1000;
        startdate=new Date(start);
        starthours=startdate.getHours();
        startmins=startdate.getMinutes();
        startsecs=startdate.getSeconds();
        System.out.println("SDATE: "+startdate);

        while(i<=477) {
            if(pk==null || pk==Packet.EOF)
            break;
            pk=jpcap_1.getPacket();
            i++;
        }
        end = pk.sec*1000 + pk.usec/1000;
        enddate=new Date(end);
        endhours=enddate.getHours();
        endmins=enddate.getMinutes();
        endsecs=enddate.getSeconds();
        System.out.println("EDATE: "+enddate);

        diff = end - start;
        diffdate = new Date(diff);
        
       
        System.out.println("\nDURATION OF TANSMISSION IS "+(java.lang.Math.abs(endhours-starthours))+"hrs "+java.lang.Math.abs(endmins-startmins)+"mins "+java.lang.Math.abs(endsecs-startsecs)+"secs");
   }



public static void print(JpcapCaptor jpcap3,int flag,int pno) throws Exception
{

   Packet pk;
   EthernetPacket epk ;
   IPPacket ipk;
   TCPPacket tpk;

    String httpmeth;
    Vector headers = new Vector();

    pk= jpcap3.getPacket();
    epk=(EthernetPacket)pk.datalink;
    ipk=(IPPacket)pk;
    tpk=(TCPPacket)ipk;

       if(pno!=0)
         for(int i=1;i<=pno;i++) {
                pk=jpcap3.getPacket();
                epk=(EthernetPacket)pk.datalink;
                ipk=(IPPacket)pk;
                tpk=(TCPPacket)ipk;
             }
        
         //Packet
         switch(flag)
         {
             case 1:
                          //PACKET INFORMATION
                         System.out.println("\nPACKET INFORMATION OF " + pno + " :\n");
                         System.out.println("PACKET CAPTURE LENGTH: "+pk.caplen);
                         
                         Date d1 = new Date((pk.sec *1000 +pk.usec/1000));
                         System.out.println("PACKET CAPTURE DATE: "+d1);
                         break;

             case 2:
                          System.out.println("\nETHERNET PACKET INFORMATION: \n");
                          switch(epk.frametype)
                         {
                              case 2054:System.out.println("FRAMETYPE: ARP");
                                        break;
                              case 2048:System.out.println( "FRAMETYPE: IP");
                                        break;

                              case -31011:System.out.println( "FRAMETYPE: IPv6");
                                          break;
                              case -28672:System.out.println( "FRAMETYPE: LOOPBACK");
                                          break;
                              case 512:System.out.println( "FRAMETYPE: PUP");
                                       break;
                              case -32715:System.out.println( "FRAMETYPE: REVARP");
                                       break;
                              case -32512:System.out.println( "FRAMETYPE: VLAN");
                                       break;
                         }

                         System.out.println("\nSOURCE MAC ADDRESS: "+epk.getSourceAddress());
                         System.out.println("\nDESTINATION MAC ADDRESS: "+epk.getDestinationAddress());
                         break;

             case 3:     //IP
                          System.out.println("\n\n\nIP PACKET INFORMATION:\n");
                          System.out.println("VERSION: "+ipk.version);
                          System.out.println("Type Of Service(TOS) PRIORITY: "+ipk.priority);
                          System.out.println("Type Of Service(TOS) THROUGHPUT: "+ipk.t_flag);
                          System.out.println("Type Of Service(TOS) RELIABILITY: "+ipk.r_flag);
                          System.out.println("LENGTH: "+ipk.length);
                          System.out.println("IDENTIFICATION: "+ipk.ident);
                          System.out.println("FRAGMENTATION - DONT FRAGMENT: "+ipk.dont_frag);
                          System.out.println("FRAGMENTATION - MORE FRAGMENT: "+ipk.more_frag);
                          System.out.println("FRAGMENTATION - OFFSET: "+ipk.offset);
                          System.out.println("TTL: "+ipk.hop_limit);
                          System.out.println("PROTOCOL: "+ipk.protocol);
                          System.out.println("SOURCE HOST IP: "+ipk.src_ip.getHostAddress());
                          System.out.println("DESTINATION HOST IP: "+ipk.dst_ip.getHostAddress());
                          break;

             case 4:      //tcp
                          System.out.println("\nTCP PACKET INFORMATION\n");
                          System.out.println("SOURCE PORT: "+ tpk.src_port);
                          System.out.println("DESTINATION PORT: "+ tpk.dst_port);
                          System.out.println("SEQUENCE NUMBER: "+ tpk.sequence);
                          System.out.println("ACK NUMBER: "+ tpk.ack_num);
                          System.out.println("URG FLAG: "+ tpk.urg);
                          System.out.println("ACK FLAG: "+ tpk.ack);
                          System.out.println("PSH FLAG: "+ tpk.psh);
                          System.out.println("RST FLAG: "+ tpk.rst);
                          System.out.println("SYN FLAG: "+ tpk.syn);
                          System.out.println("FIN FLAG: "+ tpk.fin);
                          System.out.println("WINDOW SIZE: "+tpk.window);
                          break;

             
             case 5:


                          if(((TCPPacket)pk).dst_port == 80 || ((TCPPacket)pk).src_port ==80) {
                          
                          String temp;
                          headers.removeAllElements();
                      	try
                        {

                          BufferedReader in =new BufferedReader(new StringReader(new String(pk.data)));
              		  httpmeth=in.readLine();

                          if(httpmeth==null || httpmeth.indexOf("HTTP")==-1){
				httpmeth="INVALID HTTP HEADER";
                                System.exit(0);
			  }
                        //read headers
			while((temp=in.readLine()).length()>0)
			headers.addElement(temp);
                        System.out.println(headers.toString());
                        }
                        catch(Exception e) {
                        }
                 }
            }
}
static int tcpcount=0;
static int othercount=0;
static int packets;
static int pkglen;
static int avgpkglen;
public static void getpiechart1()throws Exception
{
                
    JpcapCaptor jpcap4 = JpcapCaptor.openFile("C:\\tcp-ecn-sample.pcap");
    Packet pk4 = jpcap4.getPacket();

    
    
    packets=0;
    while(true){
     if(pk4==null || pk4==Packet.EOF)
        break;

     packets++;
     pk4 = jpcap4.getPacket();
     pkglen+=pk4.caplen;
     if(pk4 instanceof TCPPacket)
     {
             tcpcount++;
     }

    }
othercount = packets - tcpcount;
avgpkglen=pkglen/packets;
}//getpiechart1

static int srcmaccount1=0;
static int srcmaccount2=0;
static int crap=0;
static int desmaccount1=0;
static int desmaccount2=0;


public static void getpiechart2()throws Exception
    {
String mac1 = "c0:01:14:7c:00:01";
String mac2 = "c0:02:12:68:00:00";

JpcapCaptor jpcap5 = JpcapCaptor.openFile("C:\\tcp-ecn-sample.pcap");

Packet pk4 = jpcap5.getPacket();

EthernetPacket epk4 ;

int i=0;
int j=0;
int k;
int l;
int m;
while(j<335){
        j++;
  pk4 = jpcap5.getPacket();
  epk4=(EthernetPacket)pk4.datalink;

     if( epk4.getSourceAddress().equals(mac1) ){
       srcmaccount1++;
     }
     else if(epk4.getSourceAddress().equals(mac2)){
       srcmaccount2++;
    }
 else
     crap++;

}//while

    k=335;
      while(k<400) {
        k++;
        pk4 = jpcap5.getPacket();
        epk4=(EthernetPacket)pk4.datalink;



     if( epk4.getSourceAddress().equals(mac1) ){
       srcmaccount1++;
     }
     else if(epk4.getSourceAddress().equals(mac2)){
       srcmaccount2++;
     }

     if( epk4.getDestinationAddress().equals(mac1) ){
       desmaccount1++;
     }
     else if(epk4.getDestinationAddress().equals(mac2)){
       desmaccount2++;
     }


    }//while

    l=401;
    while(l<479) {
        l++;
        pk4 = jpcap5.getPacket();
        epk4=(EthernetPacket)pk4.datalink;
    


     if( epk4.getSourceAddress().equals(mac1) ){
       srcmaccount1++;
     }
     else if(epk4.getSourceAddress().equals(mac2)){
       srcmaccount2++;
      }
 if( epk4.getDestinationAddress().equals(mac1) ){
       desmaccount1++;
     }
     else if(epk4.getDestinationAddress().equals(mac2)){
       desmaccount2++;
     }
 
}


}
public PacketPrinter() {}
public PacketPrinter(String applicationTitle, String chartTitle, int flag ) {

 super(applicationTitle);

PieDataset dataset;
 if(flag==1)
 dataset = createDataset1();
 else if(flag==2)
     dataset = createDataset2();
 else if(flag==3)
     dataset = createDataset3();

 else
     dataset = createDataset1();

        JFreeChart chart = createChart(dataset, chartTitle);

        ChartPanel chartPanel = new ChartPanel(chart);

        chartPanel.setPreferredSize(new java.awt.Dimension(1100,700));

        setContentPane(chartPanel);
}


    private  PieDataset createDataset1() {
        DefaultPieDataset result = new DefaultPieDataset();
        result.setValue("TCP", tcpcount);
        result.setValue("OTHERS", othercount);
        return result;
    }
    private  PieDataset createDataset2() {
        DefaultPieDataset result = new DefaultPieDataset();
        result.setValue("MAC1(c0:01:14:7c:00:01)", srcmaccount1);
        result.setValue("MAC2(c0:02:12:68:00:0)", srcmaccount2);
        return result;
    }

      private  PieDataset createDataset3() {
        DefaultPieDataset result = new DefaultPieDataset();
        result.setValue("MAC1(c0:01:14:7c:00:01)", desmaccount1);
        result.setValue("MAC2(c0:02:12:68:00:0)", desmaccount2);
        return result;
    }


private JFreeChart createChart(PieDataset dataset, String title) {

        JFreeChart chart = ChartFactory.createPieChart3D(title,  				
            dataset,                
            true,                   
            true,
            false);

        PiePlot3D plot = (PiePlot3D) chart.getPlot();
        plot.setStartAngle(290);
        plot.setDirection(Rotation.CLOCKWISE);
        plot.setForegroundAlpha(0.5f);
        return chart;

    }

}//class
