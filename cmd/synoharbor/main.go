package main

import (
 "context"
 "errors"
 "fmt"
 "net/http/cgi"
 "os"
 "os/signal"
 "os/user"
 "strconv"
 "syscall"

 "github.com/lefterry/synoharbor/internal/api"
 "github.com/lefterry/synoharbor/internal/broker"
 "github.com/lefterry/synoharbor/internal/service"
 "github.com/lefterry/synoharbor/internal/store"
)

var version="0.1.0-dev"
func main(){syscall.Umask(0077);if e:=run();e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)}}
func run() error {
 if len(os.Args)<2{return errors.New("usage: synoharbor worker|cgi|broker|version")}
 if os.Args[1]=="version"{fmt.Println(version);return nil}
 ctx,cancel:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM);defer cancel()
 if os.Args[1]=="broker"{u,e:=user.Lookup("sc-synoharbor");if e!=nil{return e};uid,_:=strconv.Atoi(u.Uid);gid,_:=strconv.Atoi(u.Gid);return broker.Serve(ctx,broker.Socket,uid,gid,broker.NativeSystem())}
 dir:=os.Getenv("SYNOHARBOR_DATA");if dir==""{dir="/var/packages/synoharbor/var"}
 s,e:=store.Open(dir);if e!=nil{return e};defer s.Close();app:=service.New(s);defer app.ACME.Close()
 switch os.Args[1]{case "worker":return app.Run(ctx);case "cgi":return cgi.Serve(api.New(app));default:return errors.New("unknown command")}
}
